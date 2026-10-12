from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from server.database import get_db
from server.detection import drift, ml_model
from server.models import Anomaly, Device, Event, Incident, Machine, RiskScore
from server.schemas import StatsOut
from server import audit
from server.auth import current_user
from server.security import admin_or_api_key

router = APIRouter(tags=["system"])


@router.get("/stats", response_model=StatsOut, dependencies=[Depends(current_user)])
def stats(db: Session = Depends(get_db)):
    high_risk = (
        db.query(func.count(func.distinct(RiskScore.device_id))).filter(RiskScore.level.in_(["high", "critical"])).scalar()
    )
    return StatsOut(
        devices=db.query(func.count(Device.id)).scalar(),
        machines=db.query(func.count(Machine.id)).scalar(),
        events=db.query(func.count(Event.id)).scalar(),
        anomalies=db.query(func.count(Anomaly.id)).scalar(),
        open_incidents=db.query(func.count(Incident.id)).filter(Incident.status != "resolved").scalar(),
        high_risk_devices=high_risk,
        ml_trained=ml_model.status()["trained"],
    )


@router.get("/ml/status", dependencies=[Depends(current_user)])
def ml_status():
    return ml_model.status()


@router.get("/ml/drift", dependencies=[Depends(current_user)])
def ml_drift(days: float = 14, db: Session = Depends(get_db)):
    """Model health: drift of recent normal behaviour from the training baseline (PSI per feature)."""
    return drift.check(db, days)


@router.post("/ml/train")
def ml_train(db: Session = Depends(get_db), who: str = Depends(admin_or_api_key)):
    try:
        status = ml_model.train(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit.record(db, who, "ml.train", rows=status["training_rows"], excluded=status["excluded_rows"], algorithm=status["algorithm"])
    db.commit()
    return status
