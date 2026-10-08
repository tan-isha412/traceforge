from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Machine(Base):
    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String, unique=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    events: Mapped[list["Event"]] = relationship(back_populates="machine")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("vendor_id", "product_id", "serial_number", name="uq_device_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_id: Mapped[str] = mapped_column(String, index=True)
    product_id: Mapped[str] = mapped_column(String, index=True)
    serial_number: Mapped[str | None] = mapped_column(String, nullable=True)
    device_type: Mapped[str | None] = mapped_column(String, nullable=True)
    descriptor_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    events: Mapped[list["Event"]] = relationship(back_populates="device", order_by="Event.timestamp")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    machine_id: Mapped[int] = mapped_column(ForeignKey("machines.id"), index=True)
    event_type: Mapped[str] = mapped_column(String)  # "connect" | "disconnect"
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="events")
    machine: Mapped["Machine"] = relationship(back_populates="events")
    anomalies: Mapped[list["Anomaly"]] = relationship(back_populates="event", cascade="all, delete-orphan")
    risk_score: Mapped["RiskScore | None"] = relationship(back_populates="event", uselist=False, cascade="all, delete-orphan")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True)
    source: Mapped[str] = mapped_column(String)  # "rule" | "ml"
    name: Mapped[str] = mapped_column(String)
    weight: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(String)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    event: Mapped["Event"] = relationship(back_populates="anomalies")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), unique=True, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String)  # low | medium | high | critical
    reasoning: Mapped[list] = mapped_column(JSON)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    event: Mapped["Event"] = relationship(back_populates="risk_score")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    machine_id: Mapped[int] = mapped_column(ForeignKey("machines.id"), index=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_score: Mapped[float] = mapped_column(Float, default=0.0)
<<<<<<< Updated upstream
    status: Mapped[str] = mapped_column(String, default="open")
    # Incidents on different machines that involve the same device (or a clone of its serial)
    # share a case_id: the id of the first incident in the group.
    case_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    case_reason: Mapped[str | None] = mapped_column(String, nullable=True)
=======
    status: Mapped[str] = mapped_column(String, default="open")  # open | investigating | resolved
    note: Mapped[str | None] = mapped_column(String, nullable=True)
>>>>>>> Stashed changes

    device: Mapped["Device"] = relationship()
    machine: Mapped["Machine"] = relationship()
    links: Mapped[list["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)

    incident: Mapped["Incident"] = relationship(back_populates="links")
    event: Mapped["Event"] = relationship()
