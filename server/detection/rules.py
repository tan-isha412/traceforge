"""Rule-based USB checks, as standard Sigma rules (server/detection/sigma_rules, run by sigma.py).

Each event is first described as a flat document of fields. Facts that need history ("this
identity was recorded as a flash drive", "other units of this model use a different serial
format") are worked out here and stored as fields, the way a SIEM enriches events before its
rules run. The Sigma rules then decide what is suspicious, and each match becomes a Finding whose
weight is the rule's NIST SP 800-30 risk value (server/scoring/nist.py) and whose explanation is the evidence
recorded for it here.

Fields:
  device.vid_pid, device.serial, device.declared_type, device.recorded_type, device.trust_status,
  device.first_seen, device.presents_keyboard, device.serial_on_other_model,
  device.serial_fits_model, device.descriptor_changed, device.descriptor_changed_fields,
  device.fingerprint, device.fingerprint_known_for_model, device.first_time_on_machine,
  machine.hostname, machine.same_model_other_serial_24h,
  typing.keys, typing.rate_per_s, typing.median_gap_ms, typing.gap_cv, typing.first_key_after_s,
  typing.burst_fraction, typing.burst_gaps,
  transfer.bytes_written, transfer.bytes_read, transfer.over_threshold,
  transfer.unusual_for_device, event.local_hour,
  event.seconds_ahead_of_server, event.imported (any event type: rules in category usb_event)
A field is None when it does not apply (for example serial_fits_model when no other unit of the
model is known), so no rule matches on it.
"""

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.orm import Session

from server.detection import signatures, sigma
from server.models import Device, Event, Machine
from server.config import settings
from server.timeutil import as_utc, to_local

# Descriptor fields that must stay stable for a given physical device. The fingerprint
# covers the full interface/endpoint tree when the agent can read it (see fingerprint.py).
DESCRIPTOR_FIELDS = ("fingerprint", "pnp_class", "service", "interface_classes", "endpoint_count")


@dataclass
class Finding:
    source: str
    name: str
    weight: float  # NIST SP 800-30 risk value, 0-100 (server/scoring/nist.py)
    explanation: str
    detail: dict = field(default_factory=dict)


@dataclass
class Observations:
    """One event as Sigma rules see it, plus the evidence behind each rule that can match it."""

    fields: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)  # rule name -> (explanation, detail)

    def note(self, rule: str, explanation: str, detail: dict | None = None) -> None:
        self.evidence[rule] = (explanation, detail or {})


def findings_for(event_type: str, obs: Observations) -> list[Finding]:
    found = []
    for rule in sigma.evaluate(event_type, obs.fields):
        explanation, detail = obs.evidence.get(rule.name, (rule.description, {}))
        found.append(Finding("rule", rule.name, rule.risk, explanation, detail))
    return found


def serial_shape(serial: str | None) -> tuple:
    """Coarse format signature: length plus which character classes appear."""
    if not serial:
        return (0, "none")
    classes = "".join(
        sorted(
            {
                "d" if c.isdigit() else "a" if c.isalpha() else "s"
                for c in serial
            }
        )
    )
    return (len(serial), classes)


def _siblings(db: Session, device: Device) -> list[Device]:
    """Other units of the same VID/PID."""
    return (
        db.query(Device)
        .filter(Device.vendor_id == device.vendor_id, Device.product_id == device.product_id, Device.id != device.id)
        .all()
    )


# --- connect --------------------------------------------------------------------------------------


def observe_identity(obs: Observations, device: Device, machine: Machine, payload, is_new_device: bool) -> None:
    obs.fields.update(
        {
            "device.vid_pid": f"{device.vendor_id}:{device.product_id}".upper(),
            "device.serial": device.serial_number or None,
            "device.declared_type": payload.device_type or None,
            "device.recorded_type": device.device_type or None,
            "device.trust_status": device.trust_status or "auto",
            "device.first_seen": is_new_device,
            "device.presents_keyboard": signatures.presents_keyboard(payload.device_type, payload.descriptor),
            "machine.hostname": machine.hostname,
        }
    )
    obs.note("unknown_device", f"Device {device.vendor_id}:{device.product_id} has never been seen before.")
    obs.note(
        "device_type_mismatch",
        f"Identity {device.vendor_id}:{device.product_id}/{device.serial_number} was recorded as "
        f"'{device.device_type}' but now declares itself as '{payload.device_type}'.",
        {"recorded": device.device_type, "declared": payload.device_type},
    )
    board = signatures.match(device.vendor_id, device.product_id) or "programmable board"
    obs.note(
        "programmable_hid_board",
        f"{device.vendor_id}:{device.product_id} is a {board}, a programmable board often used for "
        f"keystroke injection, and it presents a keyboard interface.",
        {"board": board},
    )
    note = f" ({device.trust_note})" if device.trust_note else ""
    obs.note("blocklisted_device", f"This device was blocklisted by an investigator{note}.")


def observe_serial(obs: Observations, db: Session, device: Device, siblings: list[Device]) -> None:
    others = []
    if device.serial_number:
        # Same serial number already belongs to a device with a different VID/PID.
        others = (
            db.query(Device)
            .filter(
                Device.serial_number == device.serial_number,
                Device.id != device.id,
                (Device.vendor_id != device.vendor_id) | (Device.product_id != device.product_id),
            )
            .all()
        )
    obs.fields["device.serial_on_other_model"] = bool(others)
    if others:
        o = others[0]
        obs.note(
            "serial_reuse_across_models",
            f"Serial {device.serial_number} is already registered to {o.vendor_id}:{o.product_id} "
            f"('{o.device_type}'); this device claims {device.vendor_id}:{device.product_id}.",
            {"other_device_id": o.id},
        )

    # Another unit of the same VID/PID exists: does this serial look structurally like theirs?
    if not siblings:
        obs.fields["device.serial_fits_model"] = None
        return
    known_shapes = {serial_shape(s.serial_number) for s in siblings}
    obs.fields["device.serial_fits_model"] = serial_shape(device.serial_number) in known_shapes
    text = (
        f"Other {device.vendor_id}:{device.product_id} units use a different serial format "
        f"than '{device.serial_number or '(none)'}'."
    )
    for rule in ("missing_serial", "serial_format_mismatch"):
        obs.note(rule, text, {"known_shapes": [list(s) for s in known_shapes]})


def observe_descriptor(obs: Observations, device: Device, payload, siblings: list[Device]) -> None:
    recorded = device.descriptor_json or {}
    current = payload.descriptor or {}
    # Missing/empty values mean "not captured yet" (e.g. driver not bound), not "changed".
    diffs = {
        f: {"recorded": recorded[f], "current": current[f]}
        for f in DESCRIPTOR_FIELDS
        if recorded.get(f) not in (None, [], "")
        and current.get(f) not in (None, [], "")
        and recorded[f] != current[f]
    }
    obs.fields["device.descriptor_changed"] = bool(diffs)
    obs.fields["device.descriptor_changed_fields"] = sorted(diffs)
    if diffs:
        obs.note(
            "descriptor_mismatch",
            "USB descriptor structure differs from the recorded profile for this identity (" + ", ".join(sorted(diffs)) + ").",
            diffs,
        )

    # Does this unit's structure match any known unit of the model it claims to be?
    fingerprint = current.get("fingerprint")
    known = {(s.descriptor_json or {}).get("fingerprint") for s in siblings} - {None}
    obs.fields["device.fingerprint"] = fingerprint
    obs.fields["device.fingerprint_known_for_model"] = fingerprint in known if fingerprint and known else None
    if fingerprint and known and fingerprint not in known:
        obs.note(
            "descriptor_model_mismatch",
            f"Descriptor structure does not match any known {device.vendor_id}:{device.product_id} unit "
            f"(fingerprint {fingerprint}, expected one of {', '.join(sorted(known))}).",
            {"fingerprint": fingerprint, "known_fingerprints": sorted(known)},
        )


LOOKALIKE_WINDOW = timedelta(hours=24)


def observe_machine(obs: Observations, db: Session, device: Device, machine: Machine, event: Event) -> None:
    seen_here = (
        db.query(Event.id)
        .filter(Event.device_id == device.id, Event.machine_id == machine.id, Event.id != event.id)
        .first()
    )
    obs.fields["device.first_time_on_machine"] = seen_here is None
    obs.note("new_source_machine", f"Device has never connected to {machine.hostname} before.")

    # A unit of this model on this same machine in the last 24 hours, under a different serial:
    # the pattern of a known drive being swapped for a lookalike carrying its VID/PID.
    since = as_utc(event.timestamp) - LOOKALIKE_WINDOW
    sibling = (
        db.query(Device)
        .join(Event, Event.device_id == Device.id)
        .filter(
            Device.vendor_id == device.vendor_id,
            Device.product_id == device.product_id,
            Device.id != device.id,
            Event.machine_id == machine.id,
            Event.timestamp >= since,
            Event.id != event.id,
        )
        .first()
    )
    obs.fields["machine.same_model_other_serial_24h"] = sibling is not None
    if sibling is not None:
        obs.note(
            "same_model_new_serial",
            f"{device.vendor_id}:{device.product_id} with serial '{sibling.serial_number or '(none)'}' was on "
            f"{machine.hostname} in the last 24 hours; this unit claims the same model with serial "
            f"'{device.serial_number or '(none)'}'.",
            {"other_device_id": sibling.id},
        )


def run_rules(db: Session, device: Device, machine: Machine, event: Event, payload, is_new_device: bool) -> list[Finding]:
    obs = Observations()
    siblings = _siblings(db, device)
    observe_identity(obs, device, machine, payload, is_new_device)
    observe_serial(obs, db, device, siblings)
    observe_descriptor(obs, device, payload, siblings)
    observe_machine(obs, db, device, machine, event)
    return findings_for("connect", obs)


# --- typing ---------------------------------------------------------------------------------------

TYPING_FIELDS = ("keys", "rate_per_s", "median_gap_ms", "gap_cv", "first_key_after_s", "burst_fraction")


def check_keystroke_injection(typing: dict | None) -> list[Finding]:
    """Runs on 'typing' reports, not connects: superhuman typing from a newly connected keyboard."""
    typing = typing or {}
    obs = Observations({f"typing.{k}": typing.get(k) for k in TYPING_FIELDS})
    keys, burst = typing.get("keys") or 0, typing.get("burst_fraction")
    # Gaps under 20 ms (agent BURST_MS): too fast for a person pressing separate keys.
    burst_gaps = round(burst * (keys - 1)) if burst is not None and keys > 1 else None
    obs.fields["typing.burst_gaps"] = burst_gaps
    if "median_gap_ms" in typing:
        rate, median, cv = typing.get("rate_per_s", 0.0), typing["median_gap_ms"], typing.get("gap_cv", 1.0)
        # Name the signs that are actually present (same thresholds as usb_keystroke_injection.yml).
        signs = []
        if rate >= 25:
            signs.append(f"{rate:g} keys/s sustained")
        if median < 30 and cv < 0.35:
            signs.append(f"a median gap of {median:g} ms with almost no variation (gap CV {cv:g})")
        if burst_gaps is not None and burst_gaps >= 15 and burst >= 0.5:
            signs.append(f"{burst_gaps} gaps under 20 ms ({burst:.0%} of the typing)")
        started = typing.get("first_key_after_s")
        start = f", starting {started:g} s after it was plugged in" if started is not None else ""
        obs.note(
            "keystroke_injection",
            f"Typed {keys} keys with " + (" and ".join(signs) or "machine-like timing") + f"{start}. "
            "People type with roughly 80-250 ms between keys: this is a machine typing.",
            {**{k: typing.get(k) for k in TYPING_FIELDS}, "burst_gaps": burst_gaps},
        )
    return findings_for("typing", obs)


# --- disconnect -----------------------------------------------------------------------------------

MB = 1024 * 1024
UNUSUAL_FACTOR, UNUSUAL_MIN_MB = 10, 50  # 10x this device's usual transfer, if at least 50 MB


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024


def check_large_transfer(db: Session, device: Device, event: Event, transfer: dict | None) -> list[Finding]:
    """Runs on disconnects: a large copy to the device, by size or against its own history (T1052.001)."""
    transfer = transfer or {}
    written = transfer.get("bytes_written") or 0
    hour = to_local(event.timestamp).hour
    obs = Observations({"transfer.bytes_written": written, "transfer.bytes_read": transfer.get("bytes_read"), "event.local_hour": hour})
    if not written:
        return findings_for("disconnect", obs)

    history = [
        ((p or {}).get("transfer") or {}).get("bytes_written")  # older disconnects carry transfer=None
        for (p,) in db.query(Event.raw_payload).filter(Event.device_id == device.id, Event.event_type == "disconnect", Event.id != event.id)
    ]
    history = sorted(h for h in history if h)
    usual = history[len(history) // 2] if len(history) >= 3 else None
    obs.fields["transfer.over_threshold"] = written >= settings.exfil_threshold_mb * MB
    obs.fields["transfer.unusual_for_device"] = usual is not None and written >= UNUSUAL_FACTOR * usual and written >= UNUSUAL_MIN_MB * MB

    minutes = (transfer.get("duration_s") or 0) / 60
    why = f"{_size(written)} was written to the device" + (f" during {minutes:.0f} minutes attached" if minutes >= 1 else "")
    if usual:
        why += f"; its usual is {_size(usual)}"
    obs.note(
        "large_transfer",
        why + ". A large copy to removable storage is how data leaves on a USB stick.",
        {"bytes_written": written, "bytes_read": transfer.get("bytes_read"), "usual_bytes": usual},
    )
    obs.note("large_transfer_off_hours", f"The copy was made outside working hours ({hour:02d}:00 local).", {"local_hour": hour})
    return findings_for("disconnect", obs)


# --- any event ------------------------------------------------------------------------------------

FUTURE_TOLERANCE_S = 300  # agent clocks drift a little; usb_future_timestamp.yml flags more than this


def check_event_time(event: Event, received_at, imported: bool) -> list[Finding]:
    """Facts about the report itself, matched by the usb_event rules whatever the event type."""
    ahead = (as_utc(event.timestamp) - received_at).total_seconds()
    obs = Observations({"event.seconds_ahead_of_server": round(ahead), "event.imported": imported})
    obs.note(
        "future_timestamp",
        f"The agent dated this event {ahead / 60:.0f} minutes after the server received it. Either the agent "
        "machine's clock is wrong or the report was forged; the timeline around it is unreliable.",
        {"ahead_s": round(ahead), "received_at": received_at.isoformat()},
    )
    return findings_for("any", obs)
