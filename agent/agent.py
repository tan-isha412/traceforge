"""TraceForge live agent (Windows).

Polls Win32_PnPEntity for USB devices, diffs against the previous snapshot to
detect connect/disconnect events, and POSTs each event to the TraceForge
server. Requires: pip install wmi pywin32 requests
"""

import json
import os
import queue
import socket
import sys
import time

import requests
import wmi

SERVER_URL = os.environ.get("TRACEFORGE_SERVER", "http://localhost:8000")
POLL_INTERVAL_SECONDS = 2

# Top-level device nodes only: USB\VID_xxxx&PID_xxxx\<instance>. Interface children
# of composite devices look like ...&MI_00\... and are skipped.
PNP_ID_RE = re.compile(r"USB\\VID_(?P<vendor_id>[0-9A-Fa-f]{4})&PID_(?P<product_id>[0-9A-Fa-f]{4})\\(?P<instance>[^\\]+)$")

HOSTNAME = socket.gethostname()


def interface_classes(compatible_ids) -> set[int]:
    classes = set()
    for compatible_id in compatible_ids or ():
        match = CLASS_RE.match(compatible_id)
        if match:
            classes.add(int(match.group(1), 16))
    return classes


def parse_usb_device(pnp_device_id: str, entity) -> dict | None:
    match = PNP_ID_RE.match(pnp_device_id)
    if not match:
        return None
    instance = match.group("instance")
    # Windows invents instance IDs containing '&' for devices without a real serial number.
    serial = None if "&" in instance else instance
    return {
        "vendor_id": match.group("vendor_id").upper(),
        "product_id": match.group("product_id").upper(),
        "serial_number": serial,
        "device_type": entity.Description,
        "pnp_device_id": pnp_device_id,
        "pnp_class": entity.PNPClass,
        "service": entity.Service,
    }


def snapshot_usb_devices(conn: wmi.WMI) -> dict[str, dict]:
    devices = {}
    for entity in conn.Win32_PnPEntity():
        pnp_device_id = entity.DeviceID or ""
        if not pnp_device_id.startswith("USB\\"):
            continue
        parsed = parse_usb_device(pnp_device_id, entity)
        if parsed is not None:
            devices[pnp_device_id] = parsed
    return devices


def send_event(device: dict, event_type: str) -> None:
    payload = {
        "machine_hostname": HOSTNAME,
        "vendor_id": device["vendor_id"],
        "product_id": device["product_id"],
        "serial_number": device["serial_number"],
        "device_type": device["device_type"],
        "event_type": event_type,
        "descriptor": {
            "pnp_device_id": device["pnp_device_id"],
            "pnp_class": device["pnp_class"],
            "service": device["service"],
        },
    }
    try:
        resp = requests.post(f"{SERVER_URL}/events/ingest", json=payload, timeout=5)
        resp.raise_for_status()
        result = resp.json()
        flag = " [NEW DEVICE]" if result.get("is_new_device") else ""
        print(f"{event_type.upper():>10} {device['vendor_id']}:{device['product_id']} ({device['device_type']}){flag}")
    except requests.RequestException as exc:
        print(f"failed to send {event_type} event for {device['pnp_device_id']}: {exc}")


def run() -> None:
    conn = wmi.WMI()
    previous = snapshot_usb_devices(conn)
    print(f"TraceForge agent running on {HOSTNAME}, watching {len(previous)} USB device(s). Ctrl+C to stop.")

    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        current = snapshot_usb_devices(conn)

        for pnp_id, device in current.items():
            if pnp_id not in previous:
                send_event(device, "connect")

        for pnp_id, device in previous.items():
            if pnp_id not in current:
                send_event(device, "disconnect")

        previous = current


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        pass
