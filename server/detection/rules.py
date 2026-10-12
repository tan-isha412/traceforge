"""Rule-based USB identity checks. Each rule returns a Finding with a weight
that feeds the risk score and a human-readable explanation."""

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.orm import Session

from server.detection import signatures
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
    weight: float
    explanation: str
    detail: dict = field(default_factory=dict)


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


def check_unknown_device(device: Device, is_new_device: bool, **_) -> list[Finding]:
    if not is_new_device:
        return []
    return [
        Finding(
            "rule",
            "unknown_device",
            25,
            f"Device {device.vendor_id}:{device.product_id} has never been seen before.",
        )
    ]


def check_device_type_mismatch(device: Device, payload, **_) -> list[Finding]:
    if payload.device_type and device.device_type and payload.device_type != device.device_type:
        return [
            Finding(
                "rule",
                "device_type_mismatch",
                40,
                f"Identity {device.vendor_id}:{device.product_id}/{device.serial_number} was recorded as "
                f"'{device.device_type}' but now declares itself as '{payload.device_type}'.",
                {"recorded": device.device_type, "declared": payload.device_type},
            )
        ]
    return []


def check_serial_reuse(db: Session, device: Device, **_) -> list[Finding]:
    """Same serial number already belongs to a device with a different VID/PID."""
    if not device.serial_number:
        return []
    others = (
        db.query(Device)
        .filter(
            Device.serial_number == device.serial_number,
            Device.id != device.id,
            (Device.vendor_id != device.vendor_id) | (Device.product_id != device.product_id),
        )
        .all()
    )
    if not others:
        return []
    o = others[0]
    return [
        Finding(
            "rule",
            "serial_reuse_across_models",
            40,
            f"Serial {device.serial_number} is already registered to {o.vendor_id}:{o.product_id} "
            f"('{o.device_type}'); this device claims {device.vendor_id}:{device.product_id}.",
            {"other_device_id": o.id},
        )
    ]


def check_serial_format(db: Session, device: Device, is_new_device: bool, **_) -> list[Finding]:
    """Another unit of the same VID/PID exists but this serial looks structurally different."""
    if not is_new_device:
        return []
    siblings = (
        db.query(Device)
        .filter(
            Device.vendor_id == device.vendor_id,
            Device.product_id == device.product_id,
            Device.id != device.id,
        )
        .all()
    )
    if not siblings:
        return []
    known_shapes = {serial_shape(s.serial_number) for s in siblings}
    if serial_shape(device.serial_number) in known_shapes:
        return []
    name = "missing_serial" if not device.serial_number else "serial_format_mismatch"
    return [
        Finding(
            "rule",
            name,
            30,
            f"Other {device.vendor_id}:{device.product_id} units use a different serial format "
            f"than '{device.serial_number or '(none)'}'.",
            {"known_shapes": [list(s) for s in known_shapes]},
        )
    ]


def check_descriptor_mismatch(device: Device, payload, **_) -> list[Finding]:
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
    if not diffs:
        return []
    return [
        Finding(
            "rule",
            "descriptor_mismatch",
            35,
            "USB descriptor structure differs from the recorded profile for this identity ("
            + ", ".join(sorted(diffs))
            + ").",
            diffs,
        )
    ]


def check_descriptor_model_mismatch(db: Session, device: Device, payload, is_new_device: bool, **_) -> list[Finding]:
    """A new unit whose descriptor structure matches no known unit of the model it claims to be."""
    current = (payload.descriptor or {}).get("fingerprint")
    if not is_new_device or not current:
        return []
    siblings = (
        db.query(Device)
        .filter(Device.vendor_id == device.vendor_id, Device.product_id == device.product_id, Device.id != device.id)
        .all()
    )
    known = {(s.descriptor_json or {}).get("fingerprint") for s in siblings} - {None}
    if not known or current in known:
        return []
    return [
        Finding(
            "rule",
            "descriptor_model_mismatch",
            35,
            f"Descriptor structure does not match any known {device.vendor_id}:{device.product_id} unit "
            f"(fingerprint {current}, expected one of {', '.join(sorted(known))}).",
            {"fingerprint": current, "known_fingerprints": sorted(known)},
        )
    ]


LOOKALIKE_WINDOW = timedelta(hours=24)


def check_same_model_new_serial(db: Session, device: Device, machine: Machine, event: Event, is_new_device: bool, **_) -> list[Finding]:
    """A new unit of a model that was on this same machine in the last 24 hours, under a different serial:
    the pattern of a known drive being swapped for a lookalike carrying its VID/PID."""
    if not is_new_device:
        return []
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
    if sibling is None:
        return []
    return [
        Finding(
            "rule",
            "same_model_new_serial",
            10,
            f"{device.vendor_id}:{device.product_id} with serial '{sibling.serial_number or '(none)'}' was on "
            f"{machine.hostname} in the last 24 hours; this unit claims the same model with serial "
            f"'{device.serial_number or '(none)'}'.",
            {"other_device_id": sibling.id},
        )
    ]


def check_programmable_hid_board(device: Device, payload, **_) -> list[Finding]:
    board = signatures.match(device.vendor_id, device.product_id)
    if board is None or not signatures.presents_keyboard(payload.device_type, payload.descriptor):
        return []
    return [
        Finding(
            "rule",
            "programmable_hid_board",
            40,
            f"{device.vendor_id}:{device.product_id} is a {board}, a programmable board often used for "
            f"keystroke injection, and it presents a keyboard interface.",
            {"board": board},
        )
    ]


def check_blocklisted(device: Device, **_) -> list[Finding]:
    if device.trust_status != "blocklisted":
        return []
    note = f" ({device.trust_note})" if device.trust_note else ""
    return [Finding("rule", "blocklisted_device", 60, f"This device was blocklisted by an investigator{note}.")]


def check_new_machine(db: Session, device: Device, machine: Machine, event: Event, is_new_device: bool, **_) -> list[Finding]:
    if is_new_device:
        return []
    seen_here = (
        db.query(Event.id)
        .filter(Event.device_id == device.id, Event.machine_id == machine.id, Event.id != event.id)
        .first()
    )
    if seen_here:
        return []
    return [
        Finding(
            "rule",
            "new_source_machine",
            15,
            f"Device has never connected to {machine.hostname} before.",
        )
    ]


# People type with roughly 80-250 ms between keys and a lot of variation; injection tools type
# hundreds of keys a second with near-identical gaps.
INJECTION_MIN_KEYS = 15
INJECTION_RATE = 25.0  # keys per second
INJECTION_MEDIAN_MS = 30.0
INJECTION_MAX_CV = 0.35  # gap variation (stdev / mean); machine typing is very regular


def check_keystroke_injection(typing: dict | None) -> list[Finding]:
    """Runs on 'typing' reports, not connects: superhuman, machine-regular typing from a new keyboard."""
    if not typing or typing.get("keys", 0) < INJECTION_MIN_KEYS or "median_gap_ms" not in typing:
        return []
    rate, median, cv = typing.get("rate_per_s", 0.0), typing["median_gap_ms"], typing.get("gap_cv", 1.0)
    if rate < INJECTION_RATE and not (median < INJECTION_MEDIAN_MS and cv < INJECTION_MAX_CV):
        return []
    started = typing.get("first_key_after_s")
    start = f", starting {started:g} s after it was plugged in" if started is not None else ""
    return [
        Finding(
            "rule",
            "keystroke_injection",
            60,
            f"Typed {typing['keys']} keys at {rate:g} keys/s with a median gap of {median:g} ms and almost no variation "
            f"(gap CV {cv:g}){start}. People type with roughly 80-250 ms between keys: this is a machine typing.",
            {k: typing.get(k) for k in ("keys", "rate_per_s", "median_gap_ms", "gap_cv", "first_key_after_s", "burst_fraction")},
        )
    ]


MB = 1024 * 1024
UNUSUAL_FACTOR, UNUSUAL_MIN_MB = 10, 50  # 10x this device's usual transfer, if at least 50 MB
NIGHT = (7, 21)  # local hours outside this range count as off-hours


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024


def check_large_transfer(db: Session, device: Device, event: Event, transfer: dict | None) -> list[Finding]:
    """Runs on disconnects: a large copy to the device, by size or against its own history (T1052.001)."""
    written = (transfer or {}).get("bytes_written") or 0
    if not written:
        return []
    history = [
        ((p or {}).get("transfer") or {}).get("bytes_written")  # older disconnects carry transfer=None
        for (p,) in db.query(Event.raw_payload).filter(Event.device_id == device.id, Event.event_type == "disconnect", Event.id != event.id)
    ]
    history = sorted(h for h in history if h)
    usual = history[len(history) // 2] if len(history) >= 3 else None
    big = written >= settings.exfil_threshold_mb * MB
    unusual = usual is not None and written >= UNUSUAL_FACTOR * usual and written >= UNUSUAL_MIN_MB * MB
    if not (big or unusual):
        return []
    hour = to_local(event.timestamp).hour
    night = not NIGHT[0] <= hour < NIGHT[1]
    minutes = (transfer.get("duration_s") or 0) / 60
    why = f"{_size(written)} was written to the device" + (f" during {minutes:.0f} minutes attached" if minutes >= 1 else "")
    if usual:
        why += f"; its usual is {_size(usual)}"
    if night:
        why += f", outside working hours ({hour:02d}:00 local)"
    return [
        Finding(
            "rule",
            "large_transfer",
            50 if night else 35,
            why + ". A large copy to removable storage is how data leaves on a USB stick.",
            {"bytes_written": written, "bytes_read": transfer.get("bytes_read"), "usual_bytes": usual, "night": night},
        )
    ]


RULES = [
    check_unknown_device,
    check_device_type_mismatch,
    check_serial_reuse,
    check_serial_format,
    check_descriptor_mismatch,
    check_descriptor_model_mismatch,
    check_same_model_new_serial,
    check_programmable_hid_board,
    check_blocklisted,
    check_new_machine,
]

# An allowlisted (trusted) device may roam between machines; identity, descriptor and behaviour
# checks still apply, so a clone of a trusted device is still caught.
SILENCED_WHEN_TRUSTED = {"new_source_machine"}


def run_rules(db: Session, **ctx) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(db=db, **ctx))
    if ctx["device"].trust_status == "trusted":
        findings = [f for f in findings if f.name not in SILENCED_WHEN_TRUSTED]
    return findings
