from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, computed_field

from server.detection import sigma
from server.detection.mitre import techniques_for

from server.timeutil import as_utc

# SQLite returns naive datetimes; this makes every timestamp explicitly UTC in the JSON output.
UTCDatetime = Annotated[datetime, AfterValidator(as_utc)]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EventIngest(BaseModel):
    machine_hostname: str = Field(min_length=1, max_length=255)
    vendor_id: str = Field(min_length=1, max_length=16)
    product_id: str = Field(min_length=1, max_length=16)
    serial_number: str | None = None
    device_type: str | None = None
    # "typing" is a keystroke-timing report for a newly connected keyboard (agent/keystrokes.py).
    event_type: Literal["connect", "disconnect", "typing"]
    timestamp: UTCDatetime | None = None
    descriptor: dict | None = None
    # How the device enumerated: {"interface_order": [class codes in arrival order], "duration_ms": float}
    enumeration: dict | None = None
    # Where the event came from: None for the live agent, "import:setupapi" etc. for imported evidence.
    source: str | None = None
    evidence: dict | None = None  # the imported file and line context, for chain of custody
    # Keystroke timing from a new keyboard (agent/keystrokes.py): counts and gaps only, never which keys.
    typing: dict | None = None
    # Bytes moved while a storage device was attached (agent/transfer.py), sent with its disconnect.
    transfer: dict | None = None


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

    @computed_field
    @property
    def mitre(self) -> list[dict]:
        return techniques_for(self.name)

    @computed_field
    @property
    def rule(self) -> dict | None:
        """The Sigma rule behind a rule finding (None for ML findings)."""
        r = sigma.BY_NAME.get(self.name) if self.source == "rule" else None
        return {"id": r.id, "title": r.title, "level": r.level, "file": r.path} if r else None


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
    record_hash: str | None = None  # this event's link in the evidence chain
    transfer: dict | None = None  # bytes moved while attached, on disconnects
    source: str | None = None  # None for the live agent, "import:..." for imported evidence


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
    trust_score: float
    trust_level: str  # trusted | suspicious | untrusted | blocklisted
    trust_status: str  # auto | trusted | blocklisted (investigator override)


class DeviceDetailOut(DeviceOut):
    descriptor_json: dict | None
    machines: list[str]
    trust_factors: list[dict] = []
    trust_note: str | None = None


class TrustUpdate(BaseModel):
    status: Literal["auto", "trusted", "blocklisted"]
    note: str | None = Field(default=None, max_length=500)


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
    mitre: list[dict] = []  # ATT&CK techniques behind this incident's findings


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"] | None = None
    note: str | None = Field(default=None, max_length=2000)


class StoryOut(BaseModel):
    headline: str
    paragraphs: list[str]
    recommendations: list[str]


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


class AuditOut(ORM):
    id: int
    timestamp: UTCDatetime
    actor: str
    action: str
    target_type: str | None = None
    target_id: int | None = None
    detail: dict | None = None


class GraphMachine(BaseModel):
    id: int
    hostname: str
    max_risk: float


class GraphDevice(BaseModel):
    id: int
    label: str
    serial_number: str | None = None
    trust_level: str
    max_risk: float


class GraphEvent(BaseModel):
    event_id: int
    timestamp: UTCDatetime
    event_type: str
    device_id: int
    machine_id: int
    risk_score: float
    risk_level: str
    findings: list[str] = []
    mitre: list[str] = []
    incident_id: int | None = None


class GraphOut(BaseModel):
    title: str | None = None  # "Case #1" when replaying an incident's case
    start: UTCDatetime | None = None
    end: UTCDatetime | None = None
    machines: list[GraphMachine]
    devices: list[GraphDevice]
    events: list[GraphEvent]  # time order: the replay steps through these
    truncated: bool = False


class IntegrityOut(BaseModel):
    intact: bool
    events_checked: int
    chain_head: str
    first_broken_event_id: int | None = None
    problem: str | None = None


class ForensicReportOut(BaseModel):
    report_id: str
    generated_at: UTCDatetime
    evidence_integrity: IntegrityOut  # state of the whole evidence chain when the report was made
    device: DeviceDetailOut
    risk_history: list[RiskOut]
    timeline: list[TimelineEntry]
    anomalies_summary: dict[str, int]
    incidents: list[IncidentOut]
