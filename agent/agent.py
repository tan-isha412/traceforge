"""TraceForge live agent (Windows, Linux; macOS via libusb polling).

Listens for USB connect/disconnect events from the OS, waits briefly while the
device enumerates (to record which interfaces appeared, in what order and how
fast), reads the real descriptor tree with libusb, and sends each event to the
TraceForge server. Events the server cannot take right now are spooled to disk
and retried.

    python agent/agent.py

Environment: TRACEFORGE_SERVER (default http://localhost:8000),
TRACEFORGE_API_KEY (must match the server's API_KEY when one is set),
TRACEFORGE_SPOOL (default ~/.traceforge/spool.jsonl).
"""

import os
import queue
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # allow `python agent/agent.py`

from agent import backends  # noqa: E402
from agent.core import EnumerationTracker, RawEvent, Sender, build_payload  # noqa: E402
from agent.descriptors import device_type_for, read_descriptor  # noqa: E402

SERVER_URL = os.environ.get("TRACEFORGE_SERVER", "http://localhost:8000")
API_KEY = os.environ.get("TRACEFORGE_API_KEY") or None
SPOOL = Path(os.environ.get("TRACEFORGE_SPOOL", Path.home() / ".traceforge" / "spool.jsonl"))
RETRY_SECONDS = 10
HOSTNAME = socket.gethostname()


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
    sender = Sender(SERVER_URL, API_KEY, SPOOL)
    print(f"TraceForge agent on {HOSTNAME} ({mode}), {len(attached)} USB device(s) attached, "
          f"{len(sender.queue)} spooled event(s). Ctrl+C to stop.")
    last_retry = time.monotonic()

    while True:
        try:
            ev = events.get(timeout=0.25)
        except queue.Empty:
            ev = None

        if ev is not None:
            if ev.kind == "interface":
                tracker.interface_added(ev)
            elif ev.action == "add":
                tracker.device_added(ev)
            elif ev.action == "remove":
                known = attached.pop(ev.key, None)
                if not tracker.device_removed(ev.key) and known is not None:
                    known.wall = ev.wall
                    report(sender.send(build_payload(HOSTNAME, known, "disconnect", None, None)), f"DISCONNECT {known.vendor_id}:{known.product_id}")

        for dev, enumeration in tracker.due(time.monotonic()):
            descriptor = read_descriptor(dev.vendor_id, dev.product_id, dev.serial_number)
            if dev.device_type is None and descriptor:
                dev.device_type = device_type_for([i["interface_class"] for i in descriptor["interfaces"]])
            if not enumeration["interface_order"] and descriptor:
                enumeration["interface_order"] = [i["interface_class"] for i in descriptor["interfaces"]]
            attached[dev.key] = dev
            label = f"   CONNECT {dev.vendor_id}:{dev.product_id} ({dev.device_type}){' [no libusb descriptor]' if not descriptor else ''}"
            report(sender.send(build_payload(HOSTNAME, dev, "connect", descriptor, enumeration)), label)

        if sender.queue and time.monotonic() - last_retry > RETRY_SECONDS:
            last_retry = time.monotonic()
            report(sender.flush(), "  SPOOLED")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        pass
