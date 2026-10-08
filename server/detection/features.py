"""Behavioural features per connect event, computed from the device's own history."""

import math
import statistics
from datetime import timedelta

from sqlalchemy.orm import Session

from server.models import Event
from server.timeutil import as_utc, to_local

# Identity questions (unknown device, new machine, ...) belong to the rule engine;
# the model only sees behaviour, so the two layers do not double count.
FEATURE_NAMES = [
    "gap_log",  # log(1 + seconds since the device's previous connection)
    "gap_vs_baseline",  # log2(gap / this device's median gap); 0 until it has a baseline
    "hour_of_day",
    "hour_deviation",  # hours away from this device's usual connection time (circular)
    "events_last_hour",
    "events_last_day",
    "machines_seen",
    "enumeration_vs_baseline",  # log2(enumeration time / this device's median enumeration time)
    "enumeration_order_changed",  # 1 if interfaces arrived in a different order than last time
]

FEATURE_LABELS = {
    "gap_log": "inter-event timing",
    "gap_vs_baseline": "inter-event timing vs this device's baseline",
    "hour_of_day": "local time of day",
    "hour_deviation": "distance from this device's usual hour",
    "events_last_hour": "connection frequency (last hour)",
    "events_last_day": "connection frequency (last 24h)",
    "machines_seen": "number of distinct machines",
    "enumeration_vs_baseline": "enumeration time vs this device's baseline",
    "enumeration_order_changed": "interface enumeration order",
}

# A device with no history has no meaningful gap; use a neutral half-day.
NEUTRAL_GAP_SECONDS = 12 * 3600.0
MIN_BASELINE_EVENTS = 3


def _hour_distance(a: float, b: float) -> float:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def _circular_mean_hour(hours: list[float]) -> float:
    s = sum(math.sin(h / 24 * 2 * math.pi) for h in hours)
    c = sum(math.cos(h / 24 * 2 * math.pi) for h in hours)
    return (math.atan2(s, c) / (2 * math.pi) * 24) % 24


def features_from_history(history: list[tuple], current: tuple) -> list[float]:
    """history: [(timestamp, machine_id, enumeration|None)] of strictly earlier connects, oldest first.
    current: (timestamp, machine_id, enumeration|None) of the event being scored."""
    ts, machine_id, enum = as_utc(current[0]), current[1], current[2] if len(current) > 2 else None
    prior = [(as_utc(h[0]), h[1], h[2] if len(h) > 2 else None) for h in history]

    gap = max((ts - prior[-1][0]).total_seconds(), 0.0) if prior else NEUTRAL_GAP_SECONDS
    gaps = [max((b[0] - a[0]).total_seconds(), 1.0) for a, b in zip(prior, prior[1:])]
    gap_vs_baseline = math.log2(max(gap, 1.0) / statistics.median(gaps)) if len(gaps) >= MIN_BASELINE_EVENTS else 0.0

    local = to_local(ts)
    hour = local.hour + local.minute / 60
    hours = [h.hour + h.minute / 60 for h in (to_local(p[0]) for p in prior)]
    hour_dev = _hour_distance(hour, _circular_mean_hour(hours)) if len(hours) >= MIN_BASELINE_EVENTS else 0.0

    last_hour = sum(1 for p in prior if ts - p[0] <= timedelta(hours=1))
    last_day = sum(1 for p in prior if ts - p[0] <= timedelta(days=1))
    machines = {p[1] for p in prior} | {machine_id}

    enum_ms = (enum or {}).get("duration_ms")
    prior_ms = [float(p[2]["duration_ms"]) for p in prior if p[2] and p[2].get("duration_ms") is not None]
    enum_vs_baseline = (
        math.log2(max(float(enum_ms), 1.0) / max(statistics.median(prior_ms), 1.0))
        if enum_ms is not None and len(prior_ms) >= MIN_BASELINE_EVENTS
        else 0.0
    )
    order = (enum or {}).get("interface_order")
    previous_order = next((p[2]["interface_order"] for p in reversed(prior) if p[2] and p[2].get("interface_order")), None)
    order_changed = float(bool(order and previous_order and order != previous_order))

    return [
        math.log1p(gap),
        gap_vs_baseline,
        float(local.hour),
        hour_dev,
        float(last_hour),
        float(last_day),
        float(len(machines)),
        enum_vs_baseline,
        order_changed,
    ]


def _enumeration(raw_payload: dict | None) -> dict | None:
    return (raw_payload or {}).get("enumeration")


def extract_event_features(db: Session, event: Event) -> list[float]:
    rows = (
        db.query(Event.timestamp, Event.machine_id, Event.raw_payload)
        .filter(
            Event.device_id == event.device_id,
            Event.event_type == "connect",
            Event.id != event.id,
            Event.timestamp <= event.timestamp,
        )
        .order_by(Event.timestamp)
        .all()
    )
    return features_from_history(
        [(r[0], r[1], _enumeration(r[2])) for r in rows],
        (event.timestamp, event.machine_id, _enumeration(event.raw_payload)),
    )


def build_training_matrix(db: Session) -> list[list[float]]:
    """One row per historical connect event, using only data available at that moment."""
    by_device: dict[int, list[tuple]] = {}
    for dev_id, ts, mach, raw in (
        db.query(Event.device_id, Event.timestamp, Event.machine_id, Event.raw_payload)
        .filter(Event.event_type == "connect")
        .order_by(Event.timestamp)
        .all()
    ):
        by_device.setdefault(dev_id, []).append((ts, mach, _enumeration(raw)))

    rows: list[list[float]] = []
    for events in by_device.values():
        for i, cur in enumerate(events):
            rows.append(features_from_history(events[:i], cur))
    return rows
