from tests.conftest import HID, MASS, make_event


def post(client, **kw):
    r = client.post("/events/ingest", json=make_event(**kw))
    assert r.status_code == 200, r.text
    return r.json()


def anomaly_names(client, device_id):
    return {a["name"] for a in client.get("/anomalies", params={"device_id": device_id}).json()}


def test_new_device_is_unknown_and_scored_medium(client):
    out = post(client)
    assert out["is_new_device"] is True
    assert out["risk_level"] == "medium"
    assert out["incident_id"] is None
    assert anomaly_names(client, out["event"]["device_id"]) == {"unknown_device"}


def test_repeat_connection_on_same_machine_is_low_risk_and_known(client):
    post(client, ts="2026-09-01T10:00:00Z")
    post(client, kind="disconnect", ts="2026-09-01T11:00:00Z")
    out = post(client, ts="2026-09-02T10:00:00Z")
    assert out["is_new_device"] is False
    assert out["risk_level"] == "low"
    device = client.get(f"/devices/{out['event']['device_id']}").json()
    assert device["known"] is True


def test_new_source_machine_is_flagged(client):
    post(client)
    out = post(client, machine="PC-2", ts="2026-09-02T10:00:00Z")
    assert "new_source_machine" in anomaly_names(client, out["event"]["device_id"])


def test_device_type_and_descriptor_mismatch_is_critical_and_opens_incident(client):
    post(client)
    out = post(client, dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:00:00Z")
    names = anomaly_names(client, out["event"]["device_id"])
    assert {"device_type_mismatch", "descriptor_mismatch"} <= names
    assert out["risk_level"] == "high" or out["risk_level"] == "critical"
    assert out["incident_id"] is not None


def test_serial_reuse_across_models(client):
    post(client, vid="1050", pid="0407", serial="11223344", dtype="USB Input Device", descriptor=HID)
    out = post(client, vid="1D6B", pid="0104", serial="11223344", dtype="USB Input Device", descriptor=HID)
    assert "serial_reuse_across_models" in anomaly_names(client, out["event"]["device_id"])


def test_missing_serial_for_known_model(client):
    post(client, serial="ABC123456")
    out = post(client, serial=None)
    assert "missing_serial" in anomaly_names(client, out["event"]["device_id"])


def test_events_in_window_join_one_incident_and_later_ones_do_not(client):
    post(client)
    first = post(client, dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:00:00Z")
    disc = post(client, kind="disconnect", dtype="USB Input Device", descriptor=HID, ts="2026-09-02T03:05:00Z")
    assert disc["incident_id"] == first["incident_id"]
    later = post(client, dtype="USB Input Device", descriptor=HID, ts="2026-09-02T09:00:00Z")
    assert later["incident_id"] != first["incident_id"]

    detail = client.get(f"/incidents/{first['incident_id']}").json()
    assert [e["event_type"] for e in detail["timeline"]] == ["connect", "disconnect"]
    assert detail["event_count"] == 2


def test_disconnect_inherits_risk_of_its_connection(client):
    conn = post(client, dtype="USB Input Device", descriptor=HID)
    disc = post(client, kind="disconnect", dtype="USB Input Device", descriptor=HID, ts="2026-09-01T10:30:00Z")
    assert disc["risk_score"] == conn["risk_score"]


def test_timeline_is_chronological_and_carries_explanations(client):
    out = post(client, ts="2026-09-01T10:00:00Z")
    post(client, kind="disconnect", ts="2026-09-01T11:00:00Z")
    timeline = client.get(f"/devices/{out['event']['device_id']}/timeline").json()
    assert [t["event_type"] for t in timeline] == ["connect", "disconnect"]
    assert timeline[0]["anomalies"][0]["explanation"]


def test_risk_reasoning_lists_every_factor(client):
    out = post(client)
    history = client.get(f"/risk-scores/{out['event']['device_id']}").json()
    factors = {r["factor"] for r in history[0]["reasoning"]}
    assert factors == {"baseline", "unknown_device"}
    assert history[0]["score"] == sum(r["weight"] for r in history[0]["reasoning"])


def test_ml_training_needs_enough_history(client):
    post(client)
    assert client.post("/ml/train").status_code == 400
    assert client.get("/ml/status").json()["trained"] is False


def test_ml_flags_behavioural_outlier_with_shap_explanation(client):
    # 40 normal daytime connections, a day apart, one device on one machine.
    for day in range(1, 41):
        post(client, ts=f"2026-08-{day:02d}T10:00:00Z" if day <= 31 else f"2026-09-{day - 31:02d}T10:00:00Z")
    assert client.post("/ml/train").status_code == 200
    # Rapid-fire reconnects at 3am on the same machine.
    flagged = None
    for i in range(6):
        out = post(client, ts=f"2026-09-20T03:00:{i * 10:02d}Z")
        if "behavioural_outlier" in anomaly_names(client, out["event"]["device_id"]):
            flagged = out
    assert flagged is not None
    ml = [a for a in client.get("/anomalies", params={"source": "ml"}).json() if a["name"] == "behavioural_outlier"][0]
    assert ml["detail"]["drivers"], "SHAP drivers should be reported"
    assert "SHAP" in ml["explanation"]


def test_stats_and_unknown_device_404(client):
    post(client)
    s = client.get("/stats").json()
    assert s["devices"] == 1 and s["events"] == 1 and s["machines"] == 1
    assert client.get("/devices/999").status_code == 404


def test_api_timestamps_are_explicit_utc(client):
    out = post(client, ts="2026-09-01T10:00:00Z")
    timeline = client.get(f"/devices/{out['event']['device_id']}/timeline").json()
    assert timeline[0]["timestamp"].endswith("Z")
    assert timeline[0]["timestamp"].startswith("2026-09-01T10:00:00")


def test_hour_feature_uses_local_timezone():
    from datetime import datetime, timezone

    from server.detection.features import features_from_history

    # 22:30 UTC is 04:00 the next day in the default zone (Asia/Kolkata, UTC+5:30).
    features = features_from_history([], (datetime(2026, 9, 1, 22, 30, tzinfo=timezone.utc), 1))
    assert features[1] == 4.0


def test_model_trained_under_another_timezone_is_ignored(client, monkeypatch):
    from server.config import settings
    from server.detection import ml_model

    for day in range(1, 41):
        post(client, ts=f"2026-08-{day:02d}T10:00:00Z" if day <= 31 else f"2026-09-{day - 31:02d}T10:00:00Z")
    assert client.post("/ml/train").status_code == 200
    assert ml_model.status()["trained"] is True
    monkeypatch.setattr(settings, "timezone", "UTC")
    assert ml_model.status()["trained"] is False


SPOOF = dict(dtype="USB Input Device", descriptor=HID)


def test_device_hopping_to_another_machine_joins_the_same_incident(client):
    post(client)
    first = post(client, ts="2026-09-02T03:00:00Z", **SPOOF)
    hop = post(client, machine="PC-2", ts="2026-09-02T03:08:00Z", **SPOOF)
    assert hop["incident_id"] == first["incident_id"]
    detail = client.get(f"/incidents/{first['incident_id']}").json()
    assert detail["machines"] == ["PC-1", "PC-2"]


def test_second_suspicious_device_on_same_machine_joins_but_benign_one_does_not(client):
    post(client, vid="1050", pid="0407", serial="11223344", dtype="USB Input Device", descriptor=HID)
    mouse = dict(vid="046D", pid="C52B", serial="A1B2C3D4E5", dtype="USB Input Device", descriptor=HID)
    post(client, ts="2026-09-01T10:00:00Z", **mouse)  # the mouse is a known device on this machine
    first = post(client, vid="1D6B", pid="0104", serial="11223344", dtype="USB Input Device", descriptor=HID, ts="2026-09-02T14:00:00Z")
    assert first["incident_id"] is not None
    # Another cloned-serial attempt on the same machine 5 minutes later: suspicious, joins.
    second = post(client, vid="1D6B", pid="0105", serial="11223344", dtype="USB Input Device", descriptor=HID, ts="2026-09-02T14:05:00Z")
    assert second["incident_id"] == first["incident_id"]
    # A routine known device on that machine in the same window is not dragged in.
    routine = post(client, ts="2026-09-02T14:06:00Z", **mouse)
    assert routine["risk_level"] == "low" and routine["incident_id"] is None


def test_incident_workflow_status_note_and_resolved_incidents_stop_collecting(client):
    post(client)
    first = post(client, ts="2026-09-02T03:00:00Z", **SPOOF)
    iid = first["incident_id"]

    r = client.patch(f"/incidents/{iid}", json={"status": "investigating", "note": "Checking the drive."})
    assert r.status_code == 200 and r.json()["status"] == "investigating" and r.json()["note"] == "Checking the drive."
    assert client.get("/stats").json()["open_incidents"] == 1

    assert client.patch(f"/incidents/{iid}", json={"status": "bogus"}).status_code == 422
    assert client.patch("/incidents/999", json={"status": "open"}).status_code == 404

    client.patch(f"/incidents/{iid}", json={"status": "resolved"})
    assert client.get("/stats").json()["open_incidents"] == 0
    later = post(client, ts="2026-09-02T03:05:00Z", **SPOOF)
    assert later["incident_id"] != iid


def test_uncaptured_descriptor_fields_do_not_trigger_mismatch(client):
    post(client, descriptor={**MASS, "service": "USBSTOR"})
    # Driver not bound yet: service missing, interface list empty. That is "unknown", not "changed".
    out = post(client, descriptor={**MASS, "service": None, "interface_classes": []}, ts="2026-09-02T10:00:00Z")
    assert "descriptor_mismatch" not in anomaly_names(client, out["event"]["device_id"])
