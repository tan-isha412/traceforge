"""Weighted risk scoring: every contributing factor is recorded as the explanation."""

from sqlalchemy.orm import Session

from server.detection.rules import Finding
from server.models import Event, RiskScore

BASE_SCORE = 5.0
LEVELS = [(75, "critical"), (50, "high"), (25, "medium"), (0, "low")]


def level_for(score: float) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def compute_score(findings: list[Finding]) -> tuple[float, list[dict]]:
    reasoning = [{"factor": "baseline", "source": "system", "weight": BASE_SCORE, "explanation": "Baseline risk for any USB connection."}]
    for f in findings:
        reasoning.append({"factor": f.name, "source": f.source, "weight": f.weight, "explanation": f.explanation})
    score = min(100.0, sum(r["weight"] for r in reasoning))
    return round(score, 1), reasoning


def score_connect_event(db: Session, event: Event, findings: list[Finding]) -> RiskScore:
    score, reasoning = compute_score(findings)
    rs = RiskScore(event_id=event.id, device_id=event.device_id, score=score, level=level_for(score), reasoning=reasoning)
    db.add(rs)
    return rs


def score_disconnect_event(db: Session, event: Event, findings: list[Finding] | None = None) -> RiskScore:
    """A disconnect carries the risk of the connection it closes, plus anything found at unplug (a large copy)."""
    last = (
        db.query(RiskScore)
        .join(Event, Event.id == RiskScore.event_id)
        .filter(RiskScore.device_id == event.device_id, Event.event_type == "connect", Event.id != event.id)
        .order_by(Event.timestamp.desc())
        .first()
    )
    if last is None:
        score, reasoning = compute_score([])
    else:
        score = last.score
        reasoning = [{"factor": "inherited", "source": "system", "weight": last.score, "explanation": f"Inherits the risk of the preceding connection (event {last.event_id})."}]
    for f in findings or []:
        reasoning.append({"factor": f.name, "source": f.source, "weight": f.weight, "explanation": f.explanation})
    if findings:
        score = round(min(100.0, (last.score if last else BASE_SCORE) + sum(f.weight for f in findings)), 1)
    rs = RiskScore(event_id=event.id, device_id=event.device_id, score=score, level=level_for(score), reasoning=reasoning)
    db.add(rs)
    return rs
