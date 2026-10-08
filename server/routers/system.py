from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from server.database import get_db
from server.detection import ml_model
from server.models import Anomaly, Device, Event, Incident, Machine, RiskScore
from server.schemas import StatsOut
from server.security import require_api_key

router = APIRouter(tags=["system"])


@router.get("/stats", response_model=StatsOut)
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


@router.get("/ml/status")
def ml_status():
    return ml_model.status()


@router.post("/ml/train", dependencies=[Depends(require_api_key)])
def ml_train(db: Session = Depends(get_db)):
    try:
        return ml_model.train(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
