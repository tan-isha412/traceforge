from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from server.database import get_db
from server.schemas import EventIngest, IngestResult
from server.security import authorize_agent
from server.services.ingest import process_event

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=IngestResult)
def ingest_event(payload: EventIngest, x_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    reported_by = authorize_agent(x_api_key, payload.machine_hostname)
    out = process_event(db, payload, reported_by=reported_by)
    return IngestResult(
        event=out.event,
        is_new_device=out.is_new_device,
        risk_score=out.risk.score,
        risk_level=out.risk.level,
        incident_id=out.incident.id if out.incident else None,
    )
