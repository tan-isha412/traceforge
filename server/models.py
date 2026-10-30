from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
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
    # Investigator override of the computed trust: auto | trusted (allowlist) | blocklisted.
    trust_status: Mapped[str] = mapped_column(String, default="auto")
    trust_note: Mapped[str | None] = mapped_column(String, nullable=True)
    trust_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["Event"]] = relationship(back_populates="device", order_by="Event.timestamp")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    machine_id: Mapped[int] = mapped_column(ForeignKey("machines.id"), index=True)
    event_type: Mapped[str] = mapped_column(String)  # "connect" | "disconnect" | "typing"
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Tamper-evident evidence chain (see server/integrity.py).
    prev_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    record_hash: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # When the server received the report and who sent it (agent key name, "shared-key", or import).
    # The agent's own timestamp is kept as the event time: spooled events are legitimately late.
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=utcnow)
    reported_by: Mapped[str | None] = mapped_column(String, nullable=True)

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
    level: Mapped[str] = mapped_column(String)  # NIST SP 800-30: very_low | low | moderate | high | very_high
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
    status: Mapped[str] = mapped_column(String, default="open")  # open | investigating | resolved
    note: Mapped[str | None] = mapped_column(String, nullable=True)
    # Incidents on different machines that involve the same device (or a clone of its serial)
    # share a case_id: the id of the first incident in the group.
    case_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    case_reason: Mapped[str | None] = mapped_column(String, nullable=True)

    device: Mapped["Device"] = relationship()
    machine: Mapped["Machine"] = relationship()
    links: Mapped[list["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)

    incident: Mapped["Incident"] = relationship(back_populates="links")
    event: Mapped["Event"] = relationship()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)  # pbkdf2_sha256$iterations$salt$digest
    role: Mapped[str] = mapped_column(String, default="investigator")  # investigator | admin
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True)  # SHA-256 of the bearer token
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship()


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String, index=True)  # username, "anonymous" with logins off, "agent"
    action: Mapped[str] = mapped_column(String)
    target_type: Mapped[str | None] = mapped_column(String, nullable=True)
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class EvidenceImport(Base):
    """Chain of custody for evidence files imported from seized machines."""

    __tablename__ = "evidence_imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String)
    sha256: Mapped[str] = mapped_column(String, unique=True, index=True)  # of the exact bytes imported
    kind: Mapped[str] = mapped_column(String)  # setupapi | registry | linux
    machine_hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    imported_by: Mapped[str] = mapped_column(String)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    events_imported: Mapped[int] = mapped_column(Integer, default=0)
