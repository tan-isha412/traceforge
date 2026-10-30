"""Risk scoring under NIST SP 800-30 Rev. 1 and ISO/IEC 27005, with every factor recorded as the explanation.

- Each finding carries a risk value from its likelihood and impact (server/scoring/nist.py): rule
  findings take them from their Sigma rule, ML findings from the model.
- An event's risk is its findings' values added up, capped at 100: NIST SP 800-30 risk
  aggregation, where several moderate risks together can make a higher one (Chapter 2, p. 13).
  NIST discusses aggregation but does not prescribe a formula; the sum is TraceForge's choice.
- Its level is the Table I-3 level of that value: Very Low 0-4, Low 5-20, Moderate 21-79,
  High 80-95, Very High 96-100. A finding's value already lies in its own Table I-2 level, so an
  event is never rated below its worst finding.
- A device's risk belongs to the whole attachment, not to one event. Typing reports and the
  disconnect arrive after the connect, so they carry forward the riskiest event of the same
  attachment (its factors copied, tagged with the event they came from) and add their own.
  Otherwise a clean typing report would replace a suspicious connect as the device's latest
  risk, and an injection found while typing would vanish again at unplug. Carried factors are
  not new findings, so the incident correlator's 24-hour aggregation (which sums findings) does
  not count them twice.
"""

from sqlalchemy.orm import Session

from server.detection import sigma
from server.detection.rules import Finding
from server.models import Event, RiskScore
from server.scoring import nist

NO_FINDINGS = {"factor": "no_findings", "source": "system", "weight": 0.0, "explanation": "No Sigma rule or model finding matched this event."}


def level_for(score: float) -> str:
    return nist.level_for(score)


def _rating(name: str) -> dict | None:
    """The NIST SP 800-30 assessment behind a Sigma rule finding, for the risk explanation."""
    rule = sigma.BY_NAME.get(name)
    if rule is None:
        return None
    return {
        "rule": rule.title,
        "sigma_level": rule.level,
        "likelihood": rule.likelihood,
        "likelihood_level": nist.level_for(rule.likelihood),
        "impact": rule.impact,
        "impact_level": nist.level_for(rule.impact),
        "risk_level": rule.risk_level,
        "rationale": rule.rationale,
    }


def _factor(f: Finding) -> dict:
    entry = {"factor": f.name, "source": f.source, "weight": f.weight, "explanation": f.explanation}
    if (rating := _rating(f.name)) is not None:
        entry["nist"] = rating
    return entry


def compute_score(findings: list[Finding]) -> tuple[float, list[dict]]:
    reasoning = [_factor(f) for f in findings] or [dict(NO_FINDINGS)]
    score = min(100.0, sum(r["weight"] for r in reasoning))
    return round(score, 1), reasoning


def _save(db: Session, event: Event, score: float, reasoning: list[dict]) -> RiskScore:
    rs = RiskScore(event_id=event.id, device_id=event.device_id, score=score, level=level_for(score), reasoning=reasoning)
    db.add(rs)
    return rs


def score_connect_event(db: Session, event: Event, findings: list[Finding]) -> RiskScore:
    score, reasoning = compute_score(findings)
    return _save(db, event, score, reasoning)


def attachment_peak(db: Session, event: Event) -> RiskScore | None:
    """The highest-scoring connect or typing event of the attachment this event belongs to:
    everything for this device on this machine since its most recent connect."""
    connect = (
        db.query(Event)
        .filter(
            Event.device_id == event.device_id,
            Event.machine_id == event.machine_id,
            Event.event_type == "connect",
            Event.id != event.id,
            Event.timestamp <= event.timestamp,
        )
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .first()
    )
    if connect is None:
        return None
    return (
        db.query(RiskScore)
        .join(Event, Event.id == RiskScore.event_id)
        .filter(
            RiskScore.device_id == event.device_id,
            Event.machine_id == event.machine_id,
            Event.event_type.in_(("connect", "typing")),
            Event.id != event.id,
            Event.timestamp >= connect.timestamp,
            Event.timestamp <= event.timestamp,
        )
        .order_by(RiskScore.score.desc(), Event.timestamp.desc())
        .first()
    )


def score_followup_event(db: Session, event: Event, findings: list[Finding] | None = None) -> RiskScore:
    """A typing report or disconnect: the attachment's peak risk so far, plus anything found now."""
    peak = attachment_peak(db, event)
    carried = [] if peak is None else [
        {**r, "carried_from": r.get("carried_from", peak.event_id)} for r in peak.reasoning if r["factor"] != "no_findings"
    ]
    reasoning = carried + [_factor(f) for f in findings or []]
    score = round(min(100.0, sum(r["weight"] for r in reasoning)), 1)
    return _save(db, event, score, reasoning or [dict(NO_FINDINGS)])


# Kept for callers that predate typing reports.
score_disconnect_event = score_followup_event
