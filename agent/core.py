"""Platform-independent agent logic: enumeration tracking, payload building, delivery."""

import json
import os
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

from agent.spool import SpoolCipher


@dataclass
class RawEvent:
    """What a platform backend reports. kind is "device" or "interface"."""

    action: str  # "add" | "remove"
    kind: str
    key: str  # device node id; for interfaces, the parent device's id when known
    vendor_id: str
    product_id: str
    t: float = field(default_factory=time.monotonic)
    wall: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    serial_number: str | None = None
    device_type: str | None = None
    interface_class: int | None = None
    extra: dict = field(default_factory=dict)  # OS-specific descriptor hints (pnp_class, service, driver)


@dataclass
class Pending:
    event: RawEvent
    interfaces: list[tuple[float, int]] = field(default_factory=list)


class EnumerationTracker:
    """Holds each new device for a short settle window, collecting its interfaces as
    they appear, so the connect event can report enumeration order and duration."""

    def __init__(self, settle_seconds: float = 1.5):
        self.settle = settle_seconds
        self.pending: dict[str, Pending] = {}
        self.orphans: deque[RawEvent] = deque()  # interfaces seen before their device (Windows can do this)

    def _find(self, iface: RawEvent) -> Pending | None:
        if iface.key in self.pending:
            return self.pending[iface.key]
        # Windows interface nodes do not name their parent; match the pending device with the same VID/PID.
        return next(
            (p for p in self.pending.values() if (p.event.vendor_id, p.event.product_id) == (iface.vendor_id, iface.product_id)),
            None,
        )

    def device_added(self, ev: RawEvent) -> None:
        p = Pending(ev)
        for o in [o for o in self.orphans if (o.vendor_id, o.product_id) == (ev.vendor_id, ev.product_id)]:
            self.orphans.remove(o)
            p.interfaces.append((o.t, o.interface_class))
        self.pending[ev.key] = p

    def interface_added(self, ev: RawEvent) -> None:
        if ev.interface_class is None:
            return
        p = self._find(ev)
        if p is not None:
            p.interfaces.append((ev.t, ev.interface_class))
        else:
            self.orphans.append(ev)

    def device_removed(self, key: str) -> bool:
        """Drop a device that left during its settle window. Returns True if it was pending."""
        return self.pending.pop(key, None) is not None

    def due(self, now: float) -> list[tuple[RawEvent, dict]]:
        while self.orphans and now - self.orphans[0].t > self.settle:
            self.orphans.popleft()
        ready = [k for k, p in self.pending.items() if now - p.event.t >= self.settle]
        out = []
        for k in ready:
            p = self.pending.pop(k)
            ifaces = sorted(p.interfaces)
            out.append(
                (
                    p.event,
                    {
                        "interface_order": [c for _, c in ifaces],
                        "duration_ms": round(max(ifaces[-1][0] - p.event.t, 0.0) * 1000, 1) if ifaces else None,
                    },
                )
            )
        return out


def build_payload(hostname: str, ev: RawEvent, event_type: str, descriptor: dict | None, enumeration: dict | None) -> dict:
    return {
        "machine_hostname": hostname,
        "vendor_id": ev.vendor_id,
        "product_id": ev.product_id,
        "serial_number": ev.serial_number,
        "device_type": ev.device_type,
        "event_type": event_type,
        # The time the OS reported it, so events delivered late from the spool keep their real time.
        "timestamp": ev.wall.isoformat(),
        "descriptor": {**ev.extra, **(descriptor or {})} or None,
        "enumeration": enumeration,
    }


class Sender:
    """Delivers events in order. Anything the server did not accept is kept in a
    JSON-lines spool file and retried, so events survive server outages and agent restarts."""

    def __init__(self, server_url: str, api_key: str | None, spool_path: Path, session=None, timeout: float = 5,
                 ca_bundle: str | None = None, hostname: str | None = None):
        self.url = f"{server_url.rstrip('/')}/events/ingest"
        self.headers = {"X-API-Key": api_key} if api_key else {}
        self.spool_path = spool_path
        self.session = session or requests.Session()
        # Trust the TraceForge CA (server/tls.py) for these requests only, not system-wide. Passed on each
        # request rather than set on the session: requests lets a REQUESTS_CA_BUNDLE environment variable
        # silently override session.verify, but never an explicit verify= argument.
        self.request_options = {"verify": ca_bundle} if ca_bundle else {}
        self.timeout = timeout
        self.queue: deque[dict] = deque()
        # AES-256-GCM per line (agent/spool.py), keyed from the API key; plaintext only without a key.
        self.cipher = SpoolCipher(api_key, hostname or socket.gethostname())
        self.rejected = 0
        if spool_path.exists():
            self._load()

    def _load(self) -> None:
        bad = []
        for line in self.spool_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                self.queue.append(self.cipher.open(line))
            except ValueError as exc:
                bad.append((line, str(exc)))
        if bad:
            # Keep them for investigation; never send them, never silently drop them.
            rejected = self.spool_path.with_name(self.spool_path.name + ".rejected")
            with rejected.open("a") as f:
                f.writelines(line + "\n" for line, _ in bad)
            self.rejected = len(bad)
            print(f"WARNING: {len(bad)} spooled event(s) failed their integrity check ({bad[0][1]}); "
                  f"moved to {rejected} and not sent. This means the spool was tampered with or the API key changed.")
        self._persist()  # rewrite: drops rejected lines and seals any old plaintext lines

    def _persist(self) -> None:
        if self.queue:
            self.spool_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.spool_path.with_name(self.spool_path.name + ".tmp")
            tmp.write_text("".join(self.cipher.seal(p) + "\n" for p in self.queue))
            if os.name != "nt":
                os.chmod(tmp, 0o600)  # owner-only, like the other secrets TraceForge writes
            os.replace(tmp, self.spool_path)  # atomic: a crash mid-write never leaves a half-written spool
        else:
            self.spool_path.unlink(missing_ok=True)

    def send(self, payload: dict) -> list[dict]:
        self.queue.append(payload)
        return self.flush()

    def flush(self) -> list[dict]:
        """Send queued events oldest first; stop at the first failure. Returns the server responses."""
        results = []
        while self.queue:
            payload = self.queue[0]
            try:
                resp = self.session.post(self.url, json=payload, headers=self.headers, timeout=self.timeout, **self.request_options)
            except requests.exceptions.SSLError as exc:
                # Never fall back to an unverified connection: that is exactly what an impostor server wants.
                print(f"server certificate not trusted ({exc.__class__.__name__}); set TRACEFORGE_CA_BUNDLE to the "
                      f"TraceForge ca.crt. {len(self.queue)} event(s) spooled")
                break
            except requests.RequestException as exc:
                print(f"server unreachable ({exc.__class__.__name__}); {len(self.queue)} event(s) spooled")
                break
            if resp.status_code in (401, 403):
                print("server rejected the API key; set TRACEFORGE_API_KEY. Events stay spooled.")
                break
            if resp.status_code >= 500:
                print(f"server error {resp.status_code}; {len(self.queue)} event(s) spooled")
                break
            self.queue.popleft()
            if resp.status_code >= 400:
                print(f"dropping event the server refused ({resp.status_code}): {resp.text[:200]}")
                continue
            results.append(resp.json())
        self._persist()
        return results
