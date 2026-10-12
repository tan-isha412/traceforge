"""Read-side helpers shared by the routers."""

from datetime import datetime, timezone
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from server import integrity
from server.detection.mitre import techniques_for_all
from server.models import Anomaly, Device, Event, Incident, IncidentEvent, Machine, RiskScore
from server.schemas import (
    AnomalyOut,
    DeviceDetailOut,
    DeviceOut,
    ForensicReportOut,
    IncidentDetailOut,
    IncidentOut,
    RiskOut,
    TimelineEntry,
)
from server.scoring.risk import level_for
from server.scoring.trust import compute_trust


def timeline_entries(events: list[Event]) -> list[TimelineEntry]:
    return [
        TimelineEntry(
            event_id=e.id,
            timestamp=e.timestamp,
            event_type=e.event_type,
            machine_hostname=e.machine.hostname,
            risk_score=e.risk_score.score if e.risk_score else None,
            risk_level=e.risk_score.level if e.risk_score else None,
            anomalies=[AnomalyOut.model_validate(a) for a in e.anomalies],
            record_hash=e.record_hash,
            transfer=(e.raw_payload or {}).get("transfer"),
            source=(e.raw_payload or {}).get("source"),
        )
        for e in events
    ]


def device_events(db: Session, device_id: int) -> list[Event]:
    return (
        db.query(Event)
        .options(joinedload(Event.machine), joinedload(Event.anomalies), joinedload(Event.risk_score))
        .filter(Event.device_id == device_id)
        .order_by(Event.timestamp, Event.id)
        .all()
    )


def device_summary(db: Session, device: Device) -> DeviceOut:
    count, last_seen, machines = db.query(
        func.count(Event.id), func.max(Event.timestamp), func.count(func.distinct(Event.machine_id))
    ).filter(Event.device_id == device.id).one()
    connects = db.query(func.count(Event.id)).filter(Event.device_id == device.id, Event.event_type == "connect").scalar()
    trust = compute_trust(db, device)
    latest = db.query(RiskScore).filter(RiskScore.device_id == device.id).join(Event, Event.id == RiskScore.event_id).order_by(Event.timestamp.desc(), Event.id.desc()).first()
    return DeviceOut(
        id=device.id,
        vendor_id=device.vendor_id,
        product_id=device.product_id,
        serial_number=device.serial_number,
        device_type=device.device_type,
        first_seen=device.first_seen,
        last_seen=last_seen,
        event_count=count,
        machine_count=machines,
        risk_score=latest.score if latest else None,
        risk_level=latest.level if latest else None,
        known=connects >= 2,
        trust_score=trust.score,
        trust_level=trust.level,
        trust_status=trust.status,
    )


def device_detail(db: Session, device: Device) -> DeviceDetailOut:
    hostnames = [
        h
        for (h,) in db.query(Machine.hostname)
        .join(Event, Event.machine_id == Machine.id)
        .filter(Event.device_id == device.id)
        .distinct()
        .order_by(Machine.hostname)
        .all()
    ]
    return DeviceDetailOut(
        **device_summary(db, device).model_dump(),
        descriptor_json=device.descriptor_json,
        machines=hostnames,
        trust_factors=compute_trust(db, device).factors,
        trust_note=device.trust_note,
    )


def case_members(db: Session, inc: Incident) -> list[Incident]:
    if inc.case_id is None:
        return []
    return db.query(Incident).filter(Incident.case_id == inc.case_id).order_by(Incident.start_time, Incident.id).all()


def incident_summary(db: Session, inc: Incident) -> IncidentOut:
    pairs = (
        db.query(Event.device_id, Machine.hostname)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .join(Machine, Machine.id == Event.machine_id)
        .filter(IncidentEvent.incident_id == inc.id)
        .distinct()
        .all()
    )
    count = db.query(func.count(IncidentEvent.event_id)).filter(IncidentEvent.incident_id == inc.id).scalar()
    label = lambda d: f"{d.vendor_id}:{d.product_id} {d.device_type or ''}".strip()
    finding_names = [
        n
        for (n,) in db.query(Anomaly.name)
        .join(IncidentEvent, IncidentEvent.event_id == Anomaly.event_id)
        .filter(IncidentEvent.incident_id == inc.id)
        .distinct()
        .all()
    ]
    case_machines = sorted({m.machine.hostname for m in case_members(db, inc)})
    return IncidentOut(
        id=inc.id,
        device_id=inc.device_id,
        device_label=label(inc.device),
        devices=[label(db.get(Device, i)) for i in sorted({p[0] for p in pairs})],
        machines=sorted({p[1] for p in pairs}),
        start_time=inc.start_time,
        end_time=inc.end_time,
        max_score=inc.max_score,
        level=level_for(inc.max_score),
        status=inc.status,
        note=inc.note,
        event_count=count,
        case_id=inc.case_id,
        case_reason=inc.case_reason,
        case_machines=case_machines,
        mitre=techniques_for_all(finding_names, cross_machine=len(case_machines) > 1),
    )


def incident_detail(db: Session, inc: Incident) -> IncidentDetailOut:
    events = (
        db.query(Event)
        .options(joinedload(Event.machine), joinedload(Event.anomalies), joinedload(Event.risk_score))
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .filter(IncidentEvent.incident_id == inc.id)
        .order_by(Event.timestamp, Event.id)
        .all()
    )
    related = [incident_summary(db, m) for m in case_members(db, inc) if m.id != inc.id]
    return IncidentDetailOut(**incident_summary(db, inc).model_dump(), timeline=timeline_entries(events), related=related)


def device_forensic_report(db: Session, device: Device) -> ForensicReportOut:
    detail = device_detail(db, device)
    events = device_events(db, device.id)
    timeline = timeline_entries(events)
    risk_scores = (
        db.query(RiskScore)
        .join(Event, Event.id == RiskScore.event_id)
        .filter(RiskScore.device_id == device.id)
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .all()
    )

    anomalies_summary: dict[str, int] = {}
    for entry in timeline:
        for a in entry.anomalies:
            anomalies_summary[a.name] = anomalies_summary.get(a.name, 0) + 1

    incident_rows = (
        db.query(Incident)
        .join(IncidentEvent, IncidentEvent.incident_id == Incident.id)
        .join(Event, Event.id == IncidentEvent.event_id)
        .filter(Event.device_id == device.id)
        .distinct()
        .order_by(Incident.start_time.desc())
        .all()
    )
    incidents = [incident_summary(db, inc) for inc in incident_rows]

    now_utc = datetime.now(timezone.utc)
    report_id = f"TRC-FRN-{device.id:04d}-{int(now_utc.timestamp())}"

    return ForensicReportOut(
        report_id=report_id,
        generated_at=now_utc,
        evidence_integrity=integrity.verify(db),
        device=detail,
        risk_history=[RiskOut.model_validate(r) for r in risk_scores],
        timeline=timeline,
        anomalies_summary=anomalies_summary,
        incidents=incidents,
    )
