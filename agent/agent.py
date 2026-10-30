"""TraceForge live agent (Windows, Linux; macOS via libusb polling).

Listens for USB connect/disconnect events from the OS, waits briefly while the
device enumerates (to record which interfaces appeared, in what order and how
fast), reads the real descriptor tree with libusb, and sends each event to the
TraceForge server. Events the server cannot take right now are spooled to disk
and retried.

    python agent/agent.py

Environment: TRACEFORGE_SERVER (default http://localhost:8000; https://... when the server has TLS),
TRACEFORGE_CA_BUNDLE (the TraceForge ca.crt, to trust the server's HTTPS certificate),
TRACEFORGE_API_KEY (must match the server's API_KEY when one is set),
TRACEFORGE_SPOOL (default ~/.traceforge/spool.jsonl).
"""

import os
import queue
from datetime import datetime, timezone
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # allow `python agent/agent.py`

from agent import backends, keystrokes  # noqa: E402
from agent.transfer import TransferMeter  # noqa: E402
from agent.core import EnumerationTracker, RawEvent, Sender, build_payload  # noqa: E402
from agent.descriptors import device_type_for, read_descriptor  # noqa: E402

SERVER_URL = os.environ.get("TRACEFORGE_SERVER", "http://localhost:8000")
API_KEY = os.environ.get("TRACEFORGE_API_KEY") or None
CA_BUNDLE = os.environ.get("TRACEFORGE_CA_BUNDLE") or None
SPOOL = Path(os.environ.get("TRACEFORGE_SPOOL", Path.home() / ".traceforge" / "spool.jsonl"))
RETRY_SECONDS = 10
HOSTNAME = socket.gethostname()
# Watch keystroke timing (never which keys) on new keyboards; TRACEFORGE_WATCH_TYPING=0 turns it off.
WATCH_TYPING = os.environ.get("TRACEFORGE_WATCH_TYPING", "1") != "0"


# How often attached storage devices' I/O counters are read. The counters vanish at unplug, so
# whatever is written after the last sample is not counted: a shorter interval loses less.
SAMPLE_SECONDS = float(os.environ.get("TRACEFORGE_SAMPLE_S", "2"))


def is_storage(dev, descriptor: dict | None) -> bool:
    interfaces = (descriptor or {}).get("interfaces") or []
    return any(i.get("interface_class") == 8 for i in interfaces) or "storage" in (dev.device_type or "").lower()


def has_keyboard(dev, descriptor: dict | None) -> bool:
    """A HID boot keyboard interface (class 3, protocol 1), or a device the OS calls an input device."""
    interfaces = (descriptor or {}).get("interfaces") or []
    if any(i.get("interface_class") == 3 and i.get("interface_protocol") == 1 for i in interfaces):
        return True
    return "input" in (dev.device_type or "").lower() or "keyboard" in (dev.device_type or "").lower()


def plaintext_risk(server_url: str) -> bool:
    """Plain HTTP to anything but this machine exposes the key and the events on the network."""
    from urllib.parse import urlparse

    url = urlparse(server_url)
    return url.scheme == "http" and (url.hostname or "") not in ("localhost", "127.0.0.1", "::1")


def report(results: list[dict], label: str) -> None:
    for r in results:
        flag = " [NEW DEVICE]" if r.get("is_new_device") else ""
        inc = f" incident #{r['incident_id']}" if r.get("incident_id") else ""
        print(f"{label} risk={r['risk_score']} ({r['risk_level']}){flag}{inc}")


def run() -> None:
    events: queue.Queue[RawEvent] = queue.Queue()
    mode, existing = backends.start(events)
    attached = {e.key: e for e in existing}
    tracker = EnumerationTracker()
    sender = Sender(SERVER_URL, API_KEY, SPOOL, ca_bundle=CA_BUNDLE, hostname=HOSTNAME)
    print(f"TraceForge agent on {HOSTNAME} ({mode}), {len(attached)} USB device(s) attached, "
          f"{len(sender.queue)} spooled event(s). Ctrl+C to stop.")
    if not sender.cipher.encrypting:
        print("Note: no TRACEFORGE_API_KEY, so events spooled while the server is down are stored unencrypted.")
    if plaintext_risk(SERVER_URL):
        print("WARNING: sending events and the API key over plain HTTP to another machine; anyone on the network can read "
              "and replay them. Enable TLS on the server (python -m server.manage tls-init) and use https://.")
    if WATCH_TYPING and (why := keystrokes.unavailable_reason()):
        print(f"WARNING: keystroke-injection (BadUSB) detection is OFF on this machine: {why}.")
    last_retry = time.monotonic()
    typing_reports: queue.Queue[dict] = queue.Queue()  # filled by watch threads, sent from this loop
    meters: dict[str, TransferMeter] = {}  # storage devices attached now -> bytes moved since they connected
    last_sample = time.monotonic()
    watching: set[str] = set()  # devices whose keystroke timing is being watched this attachment

    def start_typing_watch(dev) -> None:
        """Watch from the moment the device appeared (dev.t), not from when its connect was sent:
        an injector starts typing within a second or two, while the settle window, descriptor read
        and network send take longer than that."""
        if not WATCH_TYPING or dev.key in watching:
            return
        watching.add(dev.key)
        keystrokes.watch_in_background(
            dev.vendor_id,
            dev.product_id,
            dev.t,
            lambda summary, dev=dev: typing_reports.put(build_payload(HOSTNAME, dev, "typing", None, None) | {
                "typing": summary, "timestamp": datetime.now(timezone.utc).isoformat(),
            }),
        )

    while True:
        try:
            ev = events.get(timeout=0.25)
        except queue.Empty:
            ev = None

        if ev is not None:
            if ev.kind == "interface":
                tracker.interface_added(ev)
                if ev.interface_class == 3:  # HID: may be a keyboard; the watcher checks before counting
                    pending = tracker._find(ev)
                    if pending is not None:
                        start_typing_watch(pending.event)
            elif ev.action == "add":
                tracker.device_added(ev)
            elif ev.action == "remove":
                watching.discard(ev.key)
                known = attached.pop(ev.key, None)
                if not tracker.device_removed(ev.key) and known is not None:
                    known.wall = ev.wall
                    payload = build_payload(HOSTNAME, known, "disconnect", None, None)
                    meter = meters.pop(ev.key, None)
                    if meter is not None and (moved := meter.totals()):
                        payload["transfer"] = moved
                    report(sender.send(payload), f"DISCONNECT {known.vendor_id}:{known.product_id}")

        for dev, enumeration in tracker.due(time.monotonic()):
            descriptor = read_descriptor(dev.vendor_id, dev.product_id, dev.serial_number)
            if dev.device_type is None and descriptor:
                dev.device_type = device_type_for([i["interface_class"] for i in descriptor["interfaces"]])
            if not enumeration["interface_order"] and descriptor:
                enumeration["interface_order"] = [i["interface_class"] for i in descriptor["interfaces"]]
            attached[dev.key] = dev
            label = f"   CONNECT {dev.vendor_id}:{dev.product_id} ({dev.device_type}){' [no libusb descriptor]' if not descriptor else ''}"
            report(sender.send(build_payload(HOSTNAME, dev, "connect", descriptor, enumeration)), label)
            if is_storage(dev, descriptor):
                meters[dev.key] = TransferMeter(dev.serial_number, dev.extra.get("sys_path"))
            if has_keyboard(dev, descriptor):
                start_typing_watch(dev)  # no-op if it already started when the HID interface appeared

        if meters and time.monotonic() - last_sample > SAMPLE_SECONDS:
            last_sample = time.monotonic()
            for meter in meters.values():
                meter.sample()  # the counters vanish at unplug, so the last sample is what gets reported

        while not typing_reports.empty():
            payload = typing_reports.get()
            report(sender.send(payload), f"    TYPING {payload['vendor_id']}:{payload['product_id']} {payload['typing']['keys']} keys")

        if sender.queue and time.monotonic() - last_retry > RETRY_SECONDS:
            last_retry = time.monotonic()
            report(sender.flush(), "  SPOOLED")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        pass
