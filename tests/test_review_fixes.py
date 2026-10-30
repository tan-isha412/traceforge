"""Regression tests for the review fixes, ported onto the Sigma + NIST SP 800-30 scoring.

Each test names the flaw it pins down, so a failure says which fix regressed.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from agent.keystrokes import summarize
from server import auth
from server.config import settings
from server.database import SessionLocal
from server.detection.rules import check_keystroke_injection
from server.detection import sigma
from tests.conftest import HID, make_event


def post(client, **kw):
    r = client.post("/events/ingest", json=make_event(**kw))
    assert r.status_code == 200, r.text
    return r.json()


def typing_event(typing, **kw):
    return {**make_event(**{"dtype": "USB Input Device", "descriptor": HID, **kw}), "event_type": "typing", "typing": typing}


KB = dict(vid="046D", pid="C31C", serial="KB100", dtype="USB Input Device", descriptor=HID)


def ducky_with_delays(pause_s=3.0, bursts=3, keys=50, gap_s=0.01):
    """A Rubber Ducky script: bursts of STRING typed 10 ms apart, separated by DELAY pauses."""
    t, times = 0.5, []
    for _ in range(bursts):
        for _ in range(keys):
            times.append(t)
            t += gap_s
        t += pause_s
    return summarize(times, connected_at=0.0, watched_s=30)


def jittered_typist(n=200, seed=1):
    import random

    rng = random.Random(seed)
    t, times = 1.0, []
    for _ in range(n):
        times.append(t)
        t += rng.uniform(0.06, 0.18)
    return summarize(times, connected_at=0.0, watched_s=30)


# --- Bug 1: a typing report used to replace the device's risk with the bare baseline -----------------


def test_clean_typing_report_keeps_the_attachment_risk(client):
    connect = post(client, **KB)
    out = client.post("/events/ingest", json=typing_event(jittered_typist(), **KB, ts="2026-09-01T10:00:31Z")).json()
    assert out["risk_score"] == connect["risk_score"]
    device = client.get("/devices").json()[0]
    assert device["risk_score"] == connect["risk_score"] and device["risk_level"] == connect["risk_level"]


def test_injection_found_while_typing_survives_the_disconnect(client):
    post(client, **KB, ts="2026-09-02T03:00:00Z")
    typed = client.post("/events/ingest", json=typing_event(ducky_with_delays(), **KB, ts="2026-09-02T03:00:31Z")).json()
    gone = post(client, **KB, kind="disconnect", ts="2026-09-02T03:05:00Z")
    assert typed["risk_level"] in ("high", "very_high")
    assert gone["risk_score"] == typed["risk_score"]  # the unplug no longer drops back to the connect's score
    factors = [r["factor"] for r in client.get(f"/risk-scores/{gone['event']['device_id']}").json()[0]["reasoning"]]
    assert "keystroke_injection" in factors


def test_followup_risk_is_scoped_to_its_own_attachment(client):
    post(client, **KB, ts="2026-09-02T03:00:00Z")
    client.post("/events/ingest", json=typing_event(ducky_with_delays(), **KB, ts="2026-09-02T03:00:31Z"))
    post(client, **KB, kind="disconnect", ts="2026-09-02T03:05:00Z")
    # Plugged in again next day and unplugged: the old injection belongs to the earlier attachment.
    again = post(client, **KB, ts="2026-09-03T10:00:00Z")
    gone = post(client, **KB, kind="disconnect", ts="2026-09-03T10:30:00Z")
    assert gone["risk_score"] == again["risk_score"]


# --- Bug 2: Ducky scripts with DELAY pauses slipped under both rate and regularity checks ------------


def test_ducky_script_with_delays_is_flagged_by_its_bursts():
    typing = ducky_with_delays()
    assert typing["rate_per_s"] < 25 and typing["gap_cv"] > 1  # the old two conditions both miss it
    [finding] = check_keystroke_injection(typing)
    assert "gaps under 20 ms" in finding.explanation


def test_fast_but_human_typing_is_not_flagged():
    assert check_keystroke_injection(jittered_typist()) == []


def test_a_handful_of_rollover_gaps_is_not_injection():
    # A fast typist rolls over keys now and then: a few sub-20 ms gaps among normal ones.
    times, t = [], 0.0
    for i in range(120):
        times.append(t)
        t += 0.012 if i % 15 == 0 else 0.14
    assert check_keystroke_injection(summarize(times, 0.0, 30)) == []


# --- Bug 3: any event_type was accepted and silently processed as a disconnect ----------------------


def test_unknown_event_type_is_rejected(client):
    r = client.post("/events/ingest", json={**make_event(), "event_type": "banana"})
    assert r.status_code == 422
    assert client.get("/stats").json()["events"] == 0


# --- Bug 4: /stats counted devices that were EVER high risk ---------------------------------------


def test_high_risk_tile_uses_each_devices_current_risk(client):
    post(client)
    post(client, serial="ABC123456", dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:00:00Z")  # type switch
    assert client.get("/stats").json()["high_risk_devices"] == 1
    # Next day it comes back as the storage stick it always was: its current risk is low again.
    calm = post(client, ts="2026-09-03T10:00:00Z")
    assert calm["risk_level"] in ("very_low", "low")
    assert client.get("/stats").json()["high_risk_devices"] == 0  # the old code still counted it


def test_drift_window_must_be_positive(client):
    assert client.get("/ml/drift", params={"days": 0}).status_code == 422
    assert client.get("/ml/drift", params={"days": 1000}).status_code == 422


# --- Design gap: agent timestamps were trusted blindly --------------------------------------------


def test_event_dated_in_the_future_is_flagged(client):
    ahead = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    out = post(client, ts=ahead)
    names = {a["name"] for a in client.get("/anomalies").json()}
    assert "future_timestamp" in names and out["event"]["id"]


def test_late_spooled_event_is_not_suspicious(client):
    post(client, ts="2026-01-01T10:00:00Z")  # months old: the agent was offline and spooled it
    assert "future_timestamp" not in {a["name"] for a in client.get("/anomalies").json()}


def test_server_records_when_and_from_whom_it_received_each_event(client):
    post(client)
    from server.models import Event

    with SessionLocal() as db:
        e = db.query(Event).one()
        assert e.received_at is not None and e.reported_by is None  # open dev mode: nobody authenticated


# --- Design gap: one shared key let any machine report as any other -------------------------------


@pytest.fixture()
def agent_keys(client, monkeypatch):
    keys = {"LAB-PC-01": "key-for-lab-1", "LAB-PC-02": "key-for-lab-2"}
    table = ",".join(f"{h}={hashlib.sha256(k.encode()).hexdigest()}" for h, k in keys.items())
    monkeypatch.setattr(settings, "agent_keys", table)
    monkeypatch.setattr(settings, "api_key", "shared-secret")
    return keys


def test_agent_key_reports_only_for_its_own_machine(agent_keys, client):
    ok = client.post("/events/ingest", json=make_event(machine="LAB-PC-01"), headers={"X-API-Key": agent_keys["LAB-PC-01"]})
    assert ok.status_code == 200
    forged = client.post("/events/ingest", json=make_event(machine="LAB-PC-02"), headers={"X-API-Key": agent_keys["LAB-PC-01"]})
    assert forged.status_code == 403 and "LAB-PC-01".lower() in forged.json()["detail"]
    from server.models import Event

    with SessionLocal() as db:
        assert [e.reported_by for e in db.query(Event)] == ["agent:lab-pc-01"]


def test_shared_key_can_be_switched_off_for_ingest(agent_keys, client, monkeypatch):
    shared = {"X-API-Key": "shared-secret"}
    assert client.post("/events/ingest", json=make_event(), headers=shared).status_code == 200
    monkeypatch.setattr(settings, "require_agent_keys", True)
    assert client.post("/events/ingest", json=make_event(), headers=shared).status_code == 403
    assert client.post("/events/ingest", json=make_event(), headers={"X-API-Key": "nope"}).status_code == 401


# --- Design gap: unlimited password guessing ------------------------------------------------------


@pytest.fixture()
def secured(client, monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(auth, "PBKDF2_ITERATIONS", 1000)
    with SessionLocal() as db:
        auth.create_user(db, "ivy", "investigator-1", "investigator")
    return client


def test_repeated_wrong_passwords_are_throttled(secured):
    for _ in range(settings.login_max_failures):
        assert secured.post("/auth/login", json={"username": "ivy", "password": "guess"}).status_code == 401
    blocked = secured.post("/auth/login", json={"username": "ivy", "password": "investigator-1"})
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0  # even the right one, for now
    other = secured.post("/auth/login", json={"username": "someone-else", "password": "guess"})
    assert other.status_code == 429  # same client address: spraying other usernames is throttled too


def test_successful_login_clears_the_failure_count(secured):
    for _ in range(settings.login_max_failures - 1):
        secured.post("/auth/login", json={"username": "ivy", "password": "guess"})
    assert secured.post("/auth/login", json={"username": "ivy", "password": "investigator-1"}).status_code == 200
    assert secured.post("/auth/login", json={"username": "ivy", "password": "guess"}).status_code == 401


# --- Standards-based scoring ---------------------------------------------------------------------


def test_keystroke_rule_in_the_sigma_file_has_the_burst_condition():
    rule = sigma.BY_NAME["keystroke_injection"]
    doc = {"typing.keys": 150, "typing.median_gap_ms": 10, "typing.rate_per_s": 19.9, "typing.gap_cv": 6.9,
           "typing.burst_fraction": 0.987, "typing.burst_gaps": 147}
    assert rule.matches(doc)
    assert not rule.matches({**doc, "typing.burst_gaps": 10})  # a few fast gaps alone are not enough


def test_future_timestamp_is_a_sigma_rule_for_every_event_type():
    rule = sigma.BY_NAME["future_timestamp"]
    assert rule.category == "usb_event" and rule.risk_level == "moderate" and rule.techniques == ["T1070.006"]


def test_risk_explanation_shows_the_nist_rating_of_each_rule(client):
    out = post(client)
    reasoning = client.get(f"/risk-scores/{out['event']['device_id']}").json()[0]["reasoning"]
    unknown = next(r for r in reasoning if r["factor"] == "unknown_device")
    rule = sigma.BY_NAME["unknown_device"]
    assert unknown["nist"]["likelihood"] == rule.likelihood and unknown["nist"]["impact"] == rule.impact
    assert unknown["nist"]["risk_level"] == rule.risk_level and unknown["weight"] == rule.risk


def test_security_status_lists_development_defaults(client):
    warnings = client.get("/system/security").json()["warnings"]
    assert any("AUTH_ENABLED" in w for w in warnings) and any("AGENT_KEYS" in w for w in warnings)


# --- Agent fixes ---------------------------------------------------------------------------------


def test_sysfs_walk_finds_disks_without_following_symlink_loops(tmp_path):
    from agent.transfer import _linux_disks

    dev = tmp_path / "1-2"
    (dev / "1-2:1.0" / "host6" / "target6:0:0" / "6:0:0:0" / "block" / "sdb").mkdir(parents=True)
    os.symlink(tmp_path, dev / "subsystem")  # sysfs-style link back up the tree
    assert _linux_disks(str(dev)) == ["sdb"]


def test_mouse_buttons_are_not_counted_as_keystrokes():
    from types import SimpleNamespace

    from agent import keystrokes

    ecodes = SimpleNamespace(EV_KEY=1, KEY_A=30, KEY_ENTER=28)
    evdev = SimpleNamespace(ecodes=ecodes)
    mouse = SimpleNamespace(capabilities=lambda: {1: [0x110, 0x111]})  # BTN_LEFT, BTN_RIGHT
    keyboard = SimpleNamespace(capabilities=lambda: {1: [28, 30, 31]})
    assert not keystrokes._is_keyboard(evdev, mouse)
    assert keystrokes._is_keyboard(evdev, keyboard)


def test_agent_says_when_keystroke_detection_cannot_run(monkeypatch):
    import builtins
    import sys as _sys

    from agent import keystrokes

    monkeypatch.setattr(_sys, "platform", "linux")
    real_import = builtins.__import__

    def no_evdev(name, *a, **kw):
        if name == "evdev":
            raise ImportError
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_evdev)
    assert "requirements-agent.txt" in keystrokes.unavailable_reason()
    monkeypatch.setattr(_sys, "platform", "win32")
    assert keystrokes.unavailable_reason() is None


def test_exfiltration_found_at_disconnect_lowers_device_trust(client):
    """Exfiltration is only detected when the stick is unplugged; trust used to ignore disconnects."""
    gb = 1024 ** 3
    post(client, ts="2026-09-01T10:00:00Z")
    out = client.post("/events/ingest", json={**make_event(kind="disconnect", ts="2026-09-01T23:30:00Z"),
                                               "transfer": {"bytes_written": 3 * gb, "bytes_read": 0, "duration_s": 600}}).json()
    assert out["risk_level"] in ("high", "very_high")
    factors = client.get(f"/devices/{out['event']['device_id']}").json()["trust_factors"]
    recent = next(f for f in factors if f["factor"] == "recent_risk")
    assert str(int(out["risk_score"])) in recent["explanation"]
