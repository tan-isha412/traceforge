"""Digital signatures on forensic exports and evidence-chain attestations (server/signing.py)."""

import base64
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from server import signing
from tests.conftest import make_event

ROOT = Path(__file__).resolve().parent.parent


def export(client):
    client.post("/events/ingest", json=make_event())
    r = client.get("/devices/1/export", params={"format": "json"})
    assert r.status_code == 200
    return r


def test_export_carries_a_valid_rsa_pss_signature(client):
    r = export(client)
    assert r.headers["X-Signature-Algorithm"] == "RSA-PSS-SHA256"
    assert r.headers["X-Signature-Key-Id"] == signing.key_id()
    assert signing.verify(r.content, r.headers["X-Signature"])
    for h in ("X-Signature", "X-Signature-Key-Id"):
        assert h in r.headers["Access-Control-Expose-Headers"]  # readable by the dashboard


def test_changing_one_byte_of_the_report_breaks_the_signature(client):
    r = export(client)
    tampered = r.content.replace(b'"event_type": "connect"', b'"event_type": "disconnect"', 1)
    assert tampered != r.content
    assert not signing.verify(tampered, r.headers["X-Signature"])


def test_a_hash_alone_can_be_forged_but_a_signature_cannot(client):
    """Why signatures and not just SHA-256: whoever edits a report can recompute its hash,
    but cannot produce a signature without the server's private key."""
    import hashlib

    r = export(client)
    forged = r.content.replace(b"PC-1", b"PC-9")
    forged_hash = hashlib.sha256(forged).hexdigest()  # trivially recomputed
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives import hashes

    forged_sig = base64.b64encode(attacker.sign(forged, signing._pss(), hashes.SHA256())).decode()
    assert forged_hash != r.headers["X-Content-SHA256"]
    assert not signing.verify(forged, forged_sig)


def test_public_key_is_published_without_login(client, monkeypatch):
    from server.config import settings

    monkeypatch.setattr(settings, "auth_enabled", True)
    body = client.get("/signing/public-key").json()
    assert body["key_id"] == signing.key_id() and body["key_bits"] == 2048 and body["public_exponent"] == 65537
    assert body["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_attestation_signs_the_chain_head(client):
    client.post("/events/ingest", json=make_event())
    head = client.get("/integrity/verify").json()["chain_head"]
    doc = client.get("/integrity/attestation").json()
    assert doc["statement"]["chain_head"] == head and doc["statement"]["intact"] is True
    assert signing.verify(signing.canonical(doc["statement"]), doc["signature"])
    doc["statement"]["events_checked"] += 1  # claim more evidence than was attested
    assert not signing.verify(signing.canonical(doc["statement"]), doc["signature"])


def test_private_key_file_is_owner_only_and_can_be_passphrase_encrypted(tmp_path, monkeypatch):
    from server.config import settings

    path = tmp_path / "k.pem"
    monkeypatch.setattr(settings, "signing_key_path", str(path))
    monkeypatch.setattr(settings, "signing_key_passphrase", "correct horse")
    monkeypatch.setattr(signing, "_key", None)
    signing.private_key()
    assert path.read_text().startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(signing, "_key", None)
    monkeypatch.setattr(settings, "signing_key_passphrase", "wrong")
    try:
        signing.private_key()
        raise AssertionError("loaded an encrypted key with the wrong passphrase")
    except RuntimeError as exc:
        assert "SIGNING_KEY_PASSPHRASE" in str(exc)
    monkeypatch.setattr(signing, "_key", None)


def test_offline_verifier_accepts_the_report_and_rejects_a_tampered_copy(client, tmp_path):
    r = export(client)
    report = tmp_path / "report.json"
    report.write_bytes(r.content)
    (tmp_path / "report.json.sig").write_text(json.dumps({
        "algorithm": r.headers["X-Signature-Algorithm"], "key_id": r.headers["X-Signature-Key-Id"],
        "sha256": r.headers["X-Content-SHA256"], "signature": r.headers["X-Signature"],
    }))
    (tmp_path / "pub.json").write_text(json.dumps(client.get("/signing/public-key").json()))
    cmd = [sys.executable, str(ROOT / "tools" / "verify_signature.py"), str(report), str(tmp_path / "report.json.sig"),
           "--public-key", str(tmp_path / "pub.json")]
    ok = subprocess.run(cmd, capture_output=True, text=True)
    assert ok.returncode == 0 and "VALID" in ok.stdout
    report.write_bytes(r.content.replace(b"PC-1", b"PC-9"))
    bad = subprocess.run(cmd, capture_output=True, text=True)
    assert bad.returncode == 1 and "INVALID" in bad.stdout and "SHA-256 mismatch" in bad.stdout


def test_offline_verifier_checks_an_attestation(client, tmp_path):
    client.post("/events/ingest", json=make_event())
    (tmp_path / "att.json").write_text(json.dumps(client.get("/integrity/attestation").json()))
    (tmp_path / "pub.pem").write_text(signing.public_key_pem())
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_signature.py"), "--attestation", str(tmp_path / "att.json"),
                          "--public-key", str(tmp_path / "pub.pem")], capture_output=True, text=True)
    assert out.returncode == 0 and "intact=True" in out.stdout
