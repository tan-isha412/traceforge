"""Device trust: how far a device has earned trust over its whole history, not just its last event.

A new device starts untrusted and earns trust through clean, consistent connections over time.
Recent high-risk events and active incidents take it away. An investigator can override the
result: "trusted" (allowlist) or "blocklisted". Every factor is returned with its reason, like
the risk score, so the number can always be explained.
"""

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from server.models import Device, Event, Incident, IncidentEvent, RiskScore
from server.timeutil import as_utc

BASE_TRUST = 50.0
CLEAN_SCORE = 25.0  # a connection scoring below this counts as clean
PER_CLEAN_CONNECTION, MAX_CLEAN_BONUS = 2.0, 30.0
PER_DAY_KNOWN, MAX_AGE_BONUS = 1 / 3, 10.0
RECENT_WINDOW = timedelta(days=30)
RECENT_RISK_FACTOR = 0.5
PER_ACTIVE_INCIDENT, MAX_INCIDENT_PENALTY = 15.0, 30.0
TRUSTED_AT, SUSPICIOUS_AT = 70.0, 40.0
OVERRIDES = ("auto", "trusted", "blocklisted")


@dataclass
class Trust:
    score: float
    level: str  # trusted | suspicious | untrusted | blocklisted
    status: str  # auto | trusted | blocklisted (the investigator's override)
    factors: list[dict] = field(default_factory=list)


def level_for(score: float) -> str:
    return "trusted" if score >= TRUSTED_AT else "suspicious" if score >= SUSPICIOUS_AT else "untrusted"


def compute_trust(db: Session, device: Device) -> Trust:
    status = device.trust_status or "auto"
    if status == "blocklisted":
        why = f"Blocklisted by an investigator{': ' + device.trust_note if device.trust_note else ''}."
        return Trust(0.0, "blocklisted", status, [{"factor": "blocklisted", "weight": -100.0, "explanation": why}])

    scored = (
        db.query(Event.timestamp, RiskScore.score, Event.event_type)
        .join(RiskScore, RiskScore.event_id == Event.id)
        .filter(Event.device_id == device.id, Event.event_type != "disconnect")
        .all()
    )
    connects = [(t, s) for t, s, kind in scored if kind == "connect"]
    recent_pool = [(t, s) for t, s, _ in scored]  # a typing report's risk counts against trust too
    factors = [{"factor": "baseline", "weight": BASE_TRUST, "explanation": "Starting trust for any device."}]
    if connects:
        clean = sum(1 for _, s in connects if s < CLEAN_SCORE)
        bonus = min(MAX_CLEAN_BONUS, clean * PER_CLEAN_CONNECTION)
        if bonus:
            factors.append({"factor": "clean_history", "weight": bonus, "explanation": f"{clean} clean connection(s) on record."})

        first, last = min(as_utc(t) for t, _ in connects), max(as_utc(t) for t, _ in connects)
        days = (last - first).total_seconds() / 86400
        age = min(MAX_AGE_BONUS, days * PER_DAY_KNOWN)
        if age >= 0.5:
            factors.append({"factor": "history_age", "weight": round(age, 1), "explanation": f"Known for {days:.0f} day(s)."})

        last = max(last, max(as_utc(t) for t, _ in recent_pool))
        recent = max(s for t, s in recent_pool if as_utc(t) >= last - RECENT_WINDOW)
        if recent:
            factors.append(
                {
                    "factor": "recent_risk",
                    "weight": -round(recent * RECENT_RISK_FACTOR, 1),
                    "explanation": f"Highest risk score in its last 30 days of activity was {recent:.0f}.",
                }
            )

    active = (
        db.query(func.count(func.distinct(Incident.id)))
        .join(IncidentEvent, IncidentEvent.incident_id == Incident.id)
        .join(Event, Event.id == IncidentEvent.event_id)
        .filter(Event.device_id == device.id, Incident.status != "resolved")
        .scalar()
    )
    if active:
        penalty = min(MAX_INCIDENT_PENALTY, active * PER_ACTIVE_INCIDENT)
        factors.append({"factor": "active_incidents", "weight": -penalty, "explanation": f"Involved in {active} unresolved incident(s)."})

    score = round(max(0.0, min(100.0, sum(f["weight"] for f in factors))), 1)
    if status == "trusted":
        why = f"Marked trusted by an investigator{': ' + device.trust_note if device.trust_note else ''}."
        factors.append({"factor": "trusted_override", "weight": 0.0, "explanation": why})
        return Trust(score, "trusted", status, factors)
    return Trust(score, level_for(score), status, factors)
