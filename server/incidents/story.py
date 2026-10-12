"""A plain-English account of an incident, written from its own evidence.

Template-based on purpose: every sentence comes from stored events, findings and scores, so the
story is reproducible and can never state something the evidence does not show.
"""

from sqlalchemy.orm import Session, joinedload

from server.detection.mitre import techniques_for_all
from server.models import Event, Incident, IncidentEvent
from server.scoring.trust import compute_trust
from server.services.queries import case_members
from server.timeutil import to_local

IMPERSONATION = {"serial_reuse_across_models", "descriptor_model_mismatch", "same_model_new_serial", "serial_format_mismatch", "missing_serial"}
KINDS = [
    # (findings that identify it, headline, recommended steps)
    (
        {"keystroke_injection"},
        "Keystroke-injection (BadUSB) attack: machine-speed typing",
        [
            "Treat the affected machines as compromised: the device typed faster than any person can.",
            "Check what ran on those machines in the seconds after the connection (shell history, PowerShell logs, new scheduled tasks, new user accounts).",
            "Blocklist the device so any return is flagged at once, and collect it for analysis.",
        ],
    ),
    (
        {"device_type_mismatch", "programmable_hid_board"},
        "Possible keystroke-injection (BadUSB) attack",
        [
            "Treat the affected machines as possibly compromised: a device that types can run commands in seconds.",
            "Check what ran on those machines around the connection times (shell history, PowerShell logs, new scheduled tasks).",
            "Blocklist the device so any return is flagged at once, and collect it for analysis.",
        ],
    ),
    (
        IMPERSONATION | {"descriptor_mismatch"},
        "Possible cloned or impersonated device",
        [
            "Compare the device in hand with the genuine unit it claims to be (label, serial, packaging).",
            "Blocklist the identity if the genuine device is accounted for elsewhere.",
            "Import setupapi.dev.log or kernel logs from other machines to see where else it appeared.",
        ],
    ),
    (
        {"large_transfer"},
        "Possible data exfiltration to USB storage",
        [
            "Find out what was copied: check file-access and DLP logs on the machine for the connection window.",
            "Recover the device if possible, and ask its owner why that much data was copied.",
            "If the data was sensitive, follow the data-breach procedure.",
        ],
    ),
    (
        {"blocklisted_device"},
        "A blocklisted device came back",
        ["Locate the device and whoever connected it.", "Check the machine it was connected to for changes made while it was attached."],
    ),
    (
        {"behavioural_outlier", "unseen_behaviour"},
        "Unusual behaviour from a known device",
        [
            "Confirm with the device's owner whether the activity (time, frequency, machines) was expected.",
            "If it was not, check what was copied to or from the device during the connections.",
        ],
    ),
    (
        {"unknown_device", "new_source_machine"},
        "Unfamiliar device",
        ["Identify who connected the device and why.", "Mark it trusted if it is legitimate, so it stops being flagged."],
    ),
]


def _when(ts) -> str:
    return to_local(ts).strftime("%H:%M on %d %b %Y")


def _gap(a, b) -> str:
    minutes = round((to_local(b) - to_local(a)).total_seconds() / 60)
    if minutes < 1:
        return "less than a minute later"
    if minutes < 90:
        return f"{minutes} minute{'s' if minutes != 1 else ''} later"
    hours = minutes / 60
    return f"{hours:.0f} hours later" if hours < 48 else f"{hours / 24:.0f} days later"


def _label(device) -> str:
    serial = f", serial {device.serial_number}" if device.serial_number else ", no serial number"
    return f"{device.vendor_id}:{device.product_id} ({device.device_type or 'unknown type'}{serial})"


def build_story(db: Session, incident: Incident) -> dict:
    members = case_members(db, incident) or [incident]
    events = (
        db.query(Event)
        .options(joinedload(Event.machine), joinedload(Event.device), joinedload(Event.anomalies), joinedload(Event.risk_score))
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .filter(IncidentEvent.incident_id.in_([m.id for m in members]))
        .order_by(Event.timestamp, Event.id)
        .all()
    )
    connects = [e for e in events if e.event_type == "connect"]
    typing = [a for e in events if e.event_type == "typing" for a in e.anomalies if a.name == "keystroke_injection"]
    copies = [(e, a) for e in events if e.event_type == "disconnect" for a in e.anomalies if a.name == "large_transfer"]
    if not connects:
        return {"headline": "Incident without recorded connections", "paragraphs": [], "recommendations": []}

    findings = {a.name for e in connects for a in e.anomalies} | {a.name for a in typing} | {a.name for _, a in copies}
    headline, steps = next(((h, s) for names, h, s in KINDS if names & findings), ("Suspicious USB activity", []))
    first = connects[0]
    worst = max(connects, key=lambda e: e.risk_score.score if e.risk_score else 0)
    machines_in_order = list(dict.fromkeys(e.machine.hostname for e in connects))
    paragraphs = []

    # 1. What happened first.
    opening = f"At {_when(first.timestamp)}, {_label(first.device)} connected to {first.machine.hostname}."
    first_names = {a.name for a in first.anomalies}
    if "device_type_mismatch" in first_names:
        detail = next(a for a in first.anomalies if a.name == "device_type_mismatch").detail or {}
        opening += f" It was on record as a {detail.get('recorded', 'different type')} but now declared itself a {detail.get('declared', 'new type')}."
    if "programmable_hid_board" in first_names:
        board = next(a for a in first.anomalies if a.name == "programmable_hid_board").detail.get("board")
        opening += f" It identifies as a {board}, a programmable board often used for keystroke injection, presenting a keyboard."
    if "descriptor_mismatch" in first_names or "descriptor_model_mismatch" in first_names:
        opening += " Its USB descriptor structure does not match what this identity should have."
    if first_names & IMPERSONATION - {"missing_serial"}:
        opening += " Its serial number does not fit the identity it claims."
    paragraphs.append(opening)

    if typing:
        t = typing[0].detail or {}
        started = f" {t['first_key_after_s']:g} seconds after it was plugged in," if t.get("first_key_after_s") is not None else ""
        paragraphs.append(
            f"Then,{started} it typed {t.get('keys')} keys at {t.get('rate_per_s'):g} keys per second, with a median gap of "
            f"{t.get('median_gap_ms'):g} ms between keys and almost no variation. People type with roughly 80 to 250 ms between keys: "
            "this was a machine typing, not a person. (Only the timing was recorded, never which keys.)"
        )

    for e, a in copies:
        paragraphs.append(f"When it was unplugged from {e.machine.hostname} at {_when(e.timestamp)}: {a.explanation}")

    # 2. How it spread.
    if len(machines_in_order) > 1:
        hops = []
        seen = {first.machine.hostname}
        prev = first
        for e in connects[1:]:
            host = e.machine.hostname
            if host in seen:
                continue
            same = e.device_id == first.device_id
            who = "the same device" if same else f"a device sharing its serial ({_label(e.device)})"
            hops.append(f"{_gap(prev.timestamp, e.timestamp)} {who} appeared on {host}")
            seen.add(host)
            prev = e
        span = _gap(first.timestamp, connects[-1].timestamp).replace(" later", "")
        paragraphs.append(
            "It then spread: " + "; ".join(hops) + f". In all it reached {len(machines_in_order)} machines "
            f"({', '.join(machines_in_order)}) within {span}."
        )
    elif len(connects) > 1:
        paragraphs.append(f"It connected {len(connects)} times on {first.machine.hostname} between {_when(first.timestamp)} and {_when(connects[-1].timestamp)}.")

    # 3. Why it scored what it did.
    if worst.risk_score:
        factors = sorted((r for r in worst.risk_score.reasoning if r["factor"] != "baseline"), key=lambda r: -r["weight"])[:3]
        why = "; ".join(f"{r['factor'].replace('_', ' ')} (+{r['weight']:g})" for r in factors)
        line = f"The highest-scoring connection reached {worst.risk_score.score:g}/100 ({worst.risk_score.level})"
        paragraphs.append(f"{line}, mainly from: {why}." if why else f"{line}.")
    ml = next((a for e in connects for a in e.anomalies if a.name == "behavioural_outlier"), None)
    if ml and (ml.detail or {}).get("drivers"):
        paragraphs.append("The behavioural model also found it unusual for this device: " + "; ".join(d["text"] for d in ml.detail["drivers"]) + ".")
    techniques = techniques_for_all(findings, cross_machine=len(machines_in_order) > 1)
    if techniques:
        paragraphs.append("MITRE ATT&CK: " + ", ".join(f"{t['id']} {t['name']} ({t['tactic']})" for t in techniques) + ".")

    # 4. Where it stands.
    trust = compute_trust(db, first.device)
    statuses = sorted({m.status for m in members})
    paragraphs.append(
        f"The device's trust is {trust.level} ({trust.score:g}/100). "
        f"{'This incident is' if len(members) == 1 else 'The incidents in this case are'} {', '.join(statuses)}."
    )
    if incident.note:
        paragraphs.append(f"Investigator note: {incident.note}")

    if trust.status == "blocklisted":  # do not advise what an investigator has already done
        steps = [s for s in steps if not s.startswith("Blocklist")]
    return {"headline": f"{headline}: {', '.join(machines_in_order)}", "paragraphs": paragraphs, "recommendations": steps}
