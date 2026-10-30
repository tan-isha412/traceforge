"""Standards-based detection: Sigma rules, NIST SP 800-30 Rev. 1 risk assessment, ISO/IEC 27005 risk values."""

import pytest

from server.detection import mitre, sigma, signatures
from server.scoring import nist
from tests.conftest import HID, MASS, make_event


def post(client, **kw):
    r = client.post("/events/ingest", json=make_event(**kw))
    assert r.status_code == 200, r.text
    return r.json()


VALID = {
    "title": "Test rule",
    "id": "0b6f8a51-3a52-4d0e-9a51-0e1f2a3b4c5d",
    "name": "test_rule",
    "status": "test",
    "description": "A rule for tests.",
    "author": "tests",
    "date": "2026-10-28",
    "tags": ["attack.t1200"],
    "logsource": {"product": "traceforge", "category": "usb_connect"},
    "detection": {"selection": {"device.first_seen": True}, "condition": "selection"},
    "level": "medium",
    "risk": {"likelihood": 30, "impact": 85, "rationale": "Moderate x High."},
}


# --- the rule catalogue ---------------------------------------------------------------------------


def test_every_rule_is_a_complete_sigma_rule_whose_score_fits_its_level():
    assert len(sigma.RULES) == 15
    for r in sigma.RULES:
        assert nist.SIGMA_LEVEL[r.risk_level] == r.level, r.name
        lo, hi = nist.SCALE[r.risk_level]
        assert lo <= r.risk <= hi, r.name
        assert r.rationale, r.name
        assert r.techniques and all(t in mitre.TECHNIQUES for t in r.techniques), r.name
        assert r.falsepositives and r.references, r.name


def test_attack_mapping_comes_from_the_rule_tags():
    assert mitre.FINDING_TECHNIQUES["device_type_mismatch"] == ["T1200", "T1036", "T1059"]
    assert mitre.FINDING_TECHNIQUES["large_transfer"] == ["T1052.001"]
    assert mitre.FINDING_TECHNIQUES["new_source_machine"] == ["T1091"]


def test_the_attack_board_rule_lists_the_same_boards_as_the_signatures():
    import yaml

    with (sigma.RULES_DIR / "usb_programmable_hid_board.yml").open(encoding="utf-8") as f:
        listed = yaml.safe_load(f)["detection"]["selection"]["device.vid_pid"]
    assert sorted(listed) == sorted(f"{v}:{p}" for v, p in signatures.ATTACK_BOARDS)


@pytest.mark.parametrize(
    "change, message",
    [
        ({"level": "medium", "risk": {"likelihood": 90, "impact": 90, "rationale": "x"}}, "Table I-2 gives High risk"),
        ({"risk": {"likelihood": 30, "impact": 85}}, "rationale"),
        ({"risk": {"impact": 85, "confidence": 30, "rationale": "x"}}, "likelihood and impact"),
        ({"level": "severe"}, "level must be one of"),
        ({"id": "not-a-uuid"}, "id must be a UUID"),
        ({"tags": ["attack.initial-access"]}, "ATT&CK technique"),
        ({"detection": {"selection": {"device.first_seen|regex": "x"}, "condition": "selection"}}, "unsupported modifier"),
        ({"detection": {"selection": {"device.first_seen": True}, "condition": "selection and missing"}}, "unknown search identifier"),
        ({"logsource": {"product": "windows", "category": "usb_connect"}}, "logsource"),
    ],
)
def test_a_malformed_rule_is_rejected(change, message):
    with pytest.raises(sigma.RuleError, match=message):
        sigma.parse_rule({**VALID, **change}, "test.yml")


# --- the matching engine --------------------------------------------------------------------------


def rule(detection, category="usb_connect"):
    return sigma.parse_rule({**VALID, "detection": detection, "logsource": {"product": "traceforge", "category": category}}, "test.yml")


def test_conditions_and_modifiers_follow_sigma_semantics():
    r = rule(
        {
            "volume": {"typing.keys|gte": 15},
            "fast": {"typing.rate_per_s|gte": 25},
            "regular": {"typing.median_gap_ms|lt": 30, "typing.gap_cv|lt": 0.35},
            "condition": "volume and (fast or regular)",
        }
    )
    assert r.matches({"typing.keys": 40, "typing.rate_per_s": 60})
    assert r.matches({"typing.keys": 40, "typing.rate_per_s": 10, "typing.median_gap_ms": 12, "typing.gap_cv": 0.1})
    assert not r.matches({"typing.keys": 40, "typing.rate_per_s": 10, "typing.median_gap_ms": 12, "typing.gap_cv": 0.9})
    assert not r.matches({"typing.keys": 5, "typing.rate_per_s": 60})
    assert not r.matches({})  # a missing field never matches a comparison

    r = rule({"selection": {"device.vid_pid": ["16D0:*", "2341:8036"]}, "filter": {"device.trust_status": "trusted"}, "condition": "selection and not filter"})
    assert r.matches({"device.vid_pid": "16d0:0753"})  # wildcards, case-insensitive
    assert not r.matches({"device.vid_pid": "16D0:0753", "device.trust_status": "trusted"})
    assert not r.matches({"device.vid_pid": "046D:C52B"})

    r = rule({"a": {"x|exists": True}, "same": {"x|fieldref": "y"}, "condition": "a and not same"})
    assert r.matches({"x": "keyboard", "y": "flash drive"}) and not r.matches({"x": "keyboard", "y": "keyboard"}) and not r.matches({"y": "z"})

    r = rule({"sel_a": {"n": 1}, "sel_b": {"n": 2}, "condition": "1 of sel_*"})
    assert r.matches({"n": 2}) and not r.matches({"n": 3})
    assert not rule({"selection": {"flag": True}, "condition": "selection"}).matches({"flag": 1})  # booleans are not numbers


# --- scores, levels and incidents -----------------------------------------------------------------


def test_levels_and_matrix_are_nist_sp_800_30():
    # Table I-3 ranges.
    assert [nist.level_for(v) for v in (0, 4, 5, 20, 21, 79, 80, 95, 96, 100)] == [
        "very_low", "very_low", "low", "low", "moderate", "moderate", "high", "high", "very_high", "very_high"
    ]
    # Table I-2, a few cells: likelihood x impact.
    assert nist.risk_level(50, 85) == "moderate"  # Moderate x High
    assert nist.risk_level(50, 98) == "high"  # Moderate x Very High
    assert nist.risk_level(85, 85) == "high"  # High x High
    assert nist.risk_level(10, 98) == "moderate"  # Low x Very High
    assert nist.risk_level(2, 98) == "low"  # Very Low x Very High
    # The value is likelihood x impact / 100, kept in the Table I-3 range of the Table I-2 level.
    assert nist.risk_value(30, 85) == 25.5
    assert nist.risk_value(85, 90) == 80  # 76.5 is below High's range, so it is raised to 80
    assert nist.risk_value(2, 98) == 5  # 1.96 is below Low's range


def test_a_finding_carries_its_sigma_rule_and_risk_value(client):
    out = post(client)
    assert out["risk_score"] == 25.5 and out["risk_level"] == "moderate"  # unknown_device: 30 x 85 / 100
    a = client.get("/anomalies").json()[0]
    assert a["weight"] == 25.5 and a["rule"]["level"] == "medium" and a["rule"]["file"] == "sigma_rules/usb_unknown_device.yml"


def test_rules_endpoint_lists_the_catalogue(client):
    body = client.get("/rules").json()
    assert body["levels"]["high"] == {"label": "High", "from": 80, "to": 95, "sigma_level": "high"}
    assert body["risk_matrix"]["moderate"]["very_high"] == "high"
    names = {r["name"]: r for r in body["rules"]}
    k = names["keystroke_injection"]
    assert k["event_type"] == "typing" and k["level"] == "critical" and k["risk_level"] == "very_high"
    u = names["unknown_device"]
    assert (u["likelihood_level"], u["impact_level"], u["risk_level"], u["risk_score"]) == ("moderate", "high", "moderate", 25.5)


def test_findings_that_add_up_within_a_day_open_an_incident(client):
    """NIST SP 800-30 risk aggregation: no single event is High, but the device's risk reaches High in 24 h."""
    # A device that keeps reaching new machines: unknown_device 25.5, then new_source_machine 10 per machine.
    outs = [post(client, machine=f"PC-{n}", ts=f"2026-09-01T{9 + n:02d}:00:00Z") for n in range(1, 8)]
    assert [o["risk_score"] for o in outs] == [25.5] + [10] * 6  # none High on its own
    assert [o["incident_id"] is None for o in outs] == [True] * 6 + [False]  # 25.5 + 6 x 10 = 85.5


def test_risk_older_than_the_window_does_not_add_up(client):
    post(client, machine="PC-1", ts="2026-09-01T09:00:00Z")
    for n, day in enumerate(range(2, 12), start=2):
        out = post(client, machine=f"PC-{n}", ts=f"2026-09-{day:02d}T09:00:00Z")  # one new machine a day
        assert out["incident_id"] is None


def test_a_single_high_finding_still_opens_an_incident(client):
    post(client, dtype="USB Mass Storage Device", descriptor=MASS)
    out = post(client, dtype="USB Input Device", descriptor=HID, ts="2026-09-01T10:05:00Z")
    assert out["risk_level"] in ("high", "very_high") and out["incident_id"] is not None


# --- training on real data ------------------------------------------------------------------------


def test_train_command_saves_the_model_where_it_is_told(client, tmp_path, monkeypatch, capsys):
    from server import manage
    from server.detection import ml_model

    for day in range(1, 32):
        post(client, ts=f"2026-08-{day:02d}T10:00:00Z")  # one routine connection a day
    target = tmp_path / "real.joblib"
    monkeypatch.setattr(ml_model, "MODEL_PATH", target)
    manage.run_train()
    out = capsys.readouterr().out
    assert target.exists() and "Trained iforest on 31 connection(s)" in out and str(target) in out


def test_train_command_says_when_there_is_not_enough_history(client, tmp_path, monkeypatch):
    from server import manage
    from server.detection import ml_model

    post(client)
    monkeypatch.setattr(ml_model, "MODEL_PATH", tmp_path / "real.joblib")
    with pytest.raises(SystemExit, match="at least 30"):
        manage.run_train()
