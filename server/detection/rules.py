"""Rule-based USB identity checks. Each rule returns a Finding with a weight
that feeds the risk score and a human-readable explanation."""

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from server.models import Device, Event, Machine

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


RULES = [
    check_unknown_device,
    check_device_type_mismatch,
    check_serial_reuse,
    check_serial_format,
    check_descriptor_mismatch,
    check_descriptor_model_mismatch,
    check_new_machine,
]


def run_rules(db: Session, **ctx) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(db=db, **ctx))
    return findings
