"""The full pipeline for one USB event: persist -> detect -> score -> correlate."""

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from server import integrity
from server.detection import fingerprint, ml_model
from server.detection.rules import Finding, check_event_time, check_keystroke_injection, check_large_transfer, run_rules
from server.incidents.correlate import correlate
from server.models import Anomaly, Device, Event, Incident, Machine, RiskScore
from server.schemas import EventIngest
from server.scoring.risk import score_connect_event, score_followup_event


@dataclass
class IngestOutcome:
    event: Event
    is_new_device: bool
    risk: RiskScore
    incident: Incident | None


def get_or_create_machine(db: Session, hostname: str) -> Machine:
    machine = db.query(Machine).filter(Machine.hostname == hostname).first()
    if machine is None:
        machine = Machine(hostname=hostname)
        db.add(machine)
        db.flush()
    return machine


def get_or_create_device(db: Session, payload: EventIngest) -> tuple[Device, bool]:
    device = (
        db.query(Device)
        .filter(
            Device.vendor_id == payload.vendor_id,
            Device.product_id == payload.product_id,
            Device.serial_number == payload.serial_number,
        )
        .first()
    )
    if device is not None:
        # An upgraded agent may report fields the first sighting lacked; the first value seen becomes the profile.
        recorded = device.descriptor_json or {}
        missing = {k: v for k, v in (payload.descriptor or {}).items() if k not in recorded}
        if missing:
            device.descriptor_json = {**recorded, **missing}
        return device, False

    device = Device(
        vendor_id=payload.vendor_id,
        product_id=payload.product_id,
        serial_number=payload.serial_number,
        device_type=payload.device_type,
        descriptor_json=payload.descriptor,
    )
    db.add(device)
    db.flush()
    return device, True


def process_event(db: Session, payload: EventIngest, reported_by: str | None = None) -> IngestOutcome:
    with integrity.chain_lock:
        return _process(db, payload, reported_by)


def _record(db: Session, event: Event, findings: list[Finding]) -> None:
    for f in findings:
        db.add(Anomaly(event_id=event.id, source=f.source, name=f.name, weight=f.weight, explanation=f.explanation, detail=f.detail))


def _process(db: Session, payload: EventIngest, reported_by: str | None) -> IngestOutcome:
    received_at = datetime.now(timezone.utc)
    payload = payload.model_copy(update={"descriptor": fingerprint.enrich(payload.descriptor)})
    machine = get_or_create_machine(db, payload.machine_hostname)
    device, is_new_device = get_or_create_device(db, payload)

    event = Event(
        device_id=device.id,
        machine_id=machine.id,
        event_type=payload.event_type,
        timestamp=payload.timestamp or received_at,
        raw_payload=payload.model_dump(mode="json"),
        received_at=received_at,
        reported_by=reported_by or (payload.source if payload.source else None),
    )
    db.add(event)
    db.flush()
    integrity.link(db, event)

    findings = check_event_time(event, received_at, imported=payload.source is not None)
    if payload.event_type == "connect":
        findings += run_rules(db, device=device, machine=machine, event=event, payload=payload, is_new_device=is_new_device)
        findings += ml_model.detect(db, event)
        _record(db, event, findings)
        risk = score_connect_event(db, event, findings)
    else:
        if payload.event_type == "typing":
            findings += check_keystroke_injection(payload.typing)
        else:  # disconnect
            findings += check_large_transfer(db, device, event, payload.transfer)
        _record(db, event, findings)
        risk = score_followup_event(db, event, findings)
    db.flush()

    incident = correlate(db, event, risk)
    db.commit()
    db.refresh(event)
    return IngestOutcome(event=event, is_new_device=is_new_device, risk=risk, incident=incident)
