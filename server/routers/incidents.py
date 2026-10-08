from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from server.database import get_db
from server.models import Incident
from server.schemas import IncidentDetailOut, IncidentOut, IncidentUpdate
from server.services.queries import incident_detail, incident_summary

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _get(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("", response_model=list[IncidentOut])
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.end_time.desc()).all()
    return [incident_summary(db, i) for i in incidents]


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    return incident_detail(db, _get(db, incident_id))


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, body: IncidentUpdate, db: Session = Depends(get_db)):
    incident = _get(db, incident_id)
    if body.status is not None:
        incident.status = body.status
    if body.note is not None:
        incident.note = body.note
    db.commit()
    return incident_summary(db, incident)
