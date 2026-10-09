from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from server.timeutil import as_utc

# SQLite returns naive datetimes; this makes every timestamp explicitly UTC in the JSON output.
UTCDatetime = Annotated[datetime, AfterValidator(as_utc)]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EventIngest(BaseModel):
    machine_hostname: str
    vendor_id: str
    product_id: str
    serial_number: str | None = None
    device_type: str | None = None
    event_type: str  # "connect" | "disconnect"
    timestamp: UTCDatetime | None = None
    descriptor: dict | None = None
    # How the device enumerated: {"interface_order": [class codes in arrival order], "duration_ms": float}
    enumeration: dict | None = None


class EventOut(ORM):
    id: int
    device_id: int
    machine_id: int
    event_type: str
    timestamp: UTCDatetime


class IngestResult(BaseModel):
    event: EventOut
    is_new_device: bool
    risk_score: float
    risk_level: str
    incident_id: int | None = None


class AnomalyOut(ORM):
    id: int
    event_id: int
    source: str
    name: str
    weight: float
    explanation: str
    detail: dict | None = None


class RiskOut(ORM):
    event_id: int
    device_id: int
    score: float
    level: str
    reasoning: list
    computed_at: UTCDatetime


class TimelineEntry(BaseModel):
    event_id: int
    timestamp: UTCDatetime
    event_type: str
    machine_hostname: str
    risk_score: float | None = None
    risk_level: str | None = None
    anomalies: list[AnomalyOut] = []


class DeviceOut(BaseModel):
    id: int
    vendor_id: str
    product_id: str
    serial_number: str | None
    device_type: str | None
    first_seen: UTCDatetime
    last_seen: UTCDatetime | None
    event_count: int
    machine_count: int
    risk_score: float | None
    risk_level: str | None
    known: bool


class DeviceDetailOut(DeviceOut):
    descriptor_json: dict | None
    machines: list[str]


class IncidentOut(BaseModel):
    id: int
    device_id: int
    device_label: str
    devices: list[str]
    machines: list[str]
    start_time: UTCDatetime
    end_time: UTCDatetime
    max_score: float
    level: str
    status: str
    note: str | None = None
    event_count: int
    case_id: int | None = None
    case_reason: str | None = None
    case_machines: list[str] = []  # every machine in this incident's cross-machine case


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"] | None = None
    note: str | None = Field(default=None, max_length=2000)


class IncidentDetailOut(IncidentOut):
    timeline: list[TimelineEntry]
    related: list[IncidentOut] = []  # the other incidents in the same case


class StatsOut(BaseModel):
    devices: int
    machines: int
    events: int
    anomalies: int
    open_incidents: int
    high_risk_devices: int
    ml_trained: bool


class ForensicReportOut(BaseModel):
    report_id: str
    generated_at: UTCDatetime
    device: DeviceDetailOut
    risk_history: list[RiskOut]
    timeline: list[TimelineEntry]
    anomalies_summary: dict[str, int]
    incidents: list[IncidentOut]
