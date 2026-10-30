import csv
import hashlib
import io
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from server import audit, signing
from server.auth import actor, current_user, require_role
from server.database import get_db
from server.models import Device, User
from server.schemas import DeviceDetailOut, DeviceOut, ForensicReportOut, TimelineEntry, TrustUpdate
from server.services.queries import (
    device_detail,
    device_events,
    device_forensic_report,
    device_summary,
    timeline_entries,
)

router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(current_user)])


def _get(db: Session, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("", response_model=list[DeviceOut])
def list_devices(
    q: str | None = Query(default=None, description="Search term for vendor, product, serial, or device type"),
    risk_level: str | None = Query(default=None, description="Filter by risk level (very_low, low, moderate, high, very_high: NIST SP 800-30)"),
    known: bool | None = Query(default=None, description="Filter by known status"),
    trust_level: str | None = Query(default=None, description="Filter by trust level (trusted, suspicious, untrusted, blocklisted)"),
    db: Session = Depends(get_db),
):
    summaries = [device_summary(db, d) for d in db.query(Device).all()]

    if q:
        term = q.strip().lower()
        summaries = [
            s
            for s in summaries
            if term in s.vendor_id.lower()
            or term in s.product_id.lower()
            or (s.serial_number and term in s.serial_number.lower())
            or (s.device_type and term in s.device_type.lower())
        ]

    if risk_level:
        summaries = [s for s in summaries if s.risk_level and s.risk_level.lower() == risk_level.strip().lower()]

    if known is not None:
        summaries = [s for s in summaries if s.known == known]

    if trust_level:
        summaries = [s for s in summaries if s.trust_level == trust_level.strip().lower()]

    return sorted(summaries, key=lambda d: (d.risk_score or 0, d.last_seen or d.first_seen), reverse=True)


@router.get("/{device_id}", response_model=DeviceDetailOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    return device_detail(db, _get(db, device_id))


@router.put("/{device_id}/trust", response_model=DeviceDetailOut)
def set_trust(
    device_id: int,
    body: TrustUpdate,
    db: Session = Depends(get_db),
    user: User | None = Depends(require_role("investigator")),
):
    """Investigator override: allowlist (trusted), blocklist, or back to the computed trust (auto)."""
    device = _get(db, device_id)
    audit.record(db, actor(user), "device.trust", "device", device.id, previous=device.trust_status, status=body.status, note=body.note)
    device.trust_status = body.status
    device.trust_note = body.note
    device.trust_updated_at = datetime.now(timezone.utc)
    db.commit()
    return device_detail(db, device)


@router.get("/{device_id}/timeline", response_model=list[TimelineEntry])
def get_timeline(device_id: int, db: Session = Depends(get_db)):
    _get(db, device_id)
    return timeline_entries(device_events(db, device_id))


@router.get("/{device_id}/export")
def export_device_forensic_report(
    device_id: int,
    format: Literal["json", "csv"] = "json",
    db: Session = Depends(get_db),
):
    device = _get(db, device_id)
    report = device_forensic_report(db, device)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Event ID", "Timestamp (UTC)", "Event Type", "Machine", "Risk Score", "Risk Level", "Anomalies Flagged", "Evidence Hash"])
        for entry in report.timeline:
            anomaly_str = "; ".join(f"{a.name}: {a.explanation}" for a in entry.anomalies)
            writer.writerow([
                entry.event_id,
                entry.timestamp.isoformat(),
                entry.event_type,
                entry.machine_hostname,
                entry.risk_score if entry.risk_score is not None else "",
                entry.risk_level or "",
                anomaly_str,
                entry.record_hash or "",
            ])

        filename = f"forensic_report_{device.vendor_id}_{device.product_id}_{device_id}.csv"
        return _signed_response(output.getvalue(), "text/csv", filename)

    filename = f"forensic_report_{device.vendor_id}_{device.product_id}_{device_id}.json"
    return _signed_response(report.model_dump_json(indent=2), "application/json", filename)


SIGNATURE_HEADERS = ("X-Content-SHA256", "X-Signature", "X-Signature-Algorithm", "X-Signature-Key-Id")


def _signed_response(content: str, media_type: str, filename: str) -> Response:
    """The report with its SHA-256 (integrity: the file is unchanged) and an RSA-PSS signature over
    the exact bytes sent (authenticity: this server produced it). Save the signature as a .sig
    file next to the report; tools/verify_signature.py checks them offline."""
    body = content.encode()
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-SHA256": hashlib.sha256(body).hexdigest(),
            "X-Signature": signing.sign(body),
            "X-Signature-Algorithm": signing.ALGORITHM,
            "X-Signature-Key-Id": signing.key_id(),
            "Access-Control-Expose-Headers": ", ".join(SIGNATURE_HEADERS),
        },
    )
