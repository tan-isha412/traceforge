import csv
import io
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from server.database import get_db
from server.models import Device
from server.schemas import DeviceDetailOut, DeviceOut, ForensicReportOut, TimelineEntry
from server.services.queries import (
    device_detail,
    device_events,
    device_forensic_report,
    device_summary,
    timeline_entries,
)

router = APIRouter(prefix="/devices", tags=["devices"])


def _get(db: Session, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("", response_model=list[DeviceOut])
def list_devices(
    q: str | None = Query(default=None, description="Search term for vendor, product, serial, or device type"),
    risk_level: str | None = Query(default=None, description="Filter by risk level (low, medium, high, critical)"),
    known: bool | None = Query(default=None, description="Filter by known status"),
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

    return sorted(summaries, key=lambda d: (d.risk_score or 0, d.last_seen or d.first_seen), reverse=True)


@router.get("/{device_id}", response_model=DeviceDetailOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    return device_detail(db, _get(db, device_id))


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
        writer.writerow(["Event ID", "Timestamp (UTC)", "Event Type", "Machine", "Risk Score", "Risk Level", "Anomalies Flagged"])
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
            ])

        filename = f"forensic_report_{device.vendor_id}_{device.product_id}_{device_id}.csv"
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return report
