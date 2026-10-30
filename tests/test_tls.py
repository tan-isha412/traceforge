"""HTTPS for the API (server/tls.py, server/run.py) and the agent's side of it."""

import socket
import threading
import time
from datetime import datetime, timezone

import pytest
import requests
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from agent.agent import plaintext_risk
from agent.core import Sender
from server import tls
from tests.conftest import make_event


def test_ca_and_server_certificate_are_a_valid_chain(tmp_path):
    out = tls.issue(tmp_path, ["localhost", "127.0.0.1", "traceforge-server"])
    ca = x509.load_pem_x509_certificate(out.ca_cert.read_bytes())
    srv = x509.load_pem_x509_certificate(out.server_cert.read_bytes())
    srv.verify_directly_issued_by(ca)  # raises if the signature or issuer does not match
    assert isinstance(srv.public_key(), ec.EllipticCurvePublicKey) and srv.public_key().curve.name == "secp256r1"
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert srv.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    san = srv.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "traceforge-server" in san.get_values_for_type(x509.DNSName)
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
    assert (srv.not_valid_after_utc - datetime.now(timezone.utc)).days <= tls.SERVER_DAYS
    assert out.server_key.stat().st_mode & 0o777 == 0o600 and (tmp_path / "ca.key").stat().st_mode & 0o777 == 0o600


def test_reissuing_keeps_the_ca_so_agents_keep_trusting_the_server(tmp_path):
    first = tls.issue(tmp_path, ["localhost"])
    ca_before = first.ca_cert.read_bytes()
    second = tls.issue(tmp_path, ["localhost", "10.0.0.5"])
    assert first.ca_created and not second.ca_created and second.ca_cert.read_bytes() == ca_before


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def https_server(client, tmp_path):
    """The real app served over TLS by uvicorn, as server/run.py does."""
    out = tls.issue(tmp_path, ["localhost", "127.0.0.1"])
    port = _free_port()
    config = uvicorn.Config("server.main:app", host="127.0.0.1", port=port, log_level="warning",
                            ssl_certfile=str(out.server_cert), ssl_keyfile=str(out.server_key))
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"https://localhost:{port}", out.ca_cert
    server.should_exit = True
    thread.join(timeout=5)


def test_agent_delivers_over_https_when_it_trusts_the_ca(https_server, tmp_path):
    url, ca = https_server
    sender = Sender(url, None, tmp_path / "spool.jsonl", ca_bundle=str(ca))
    [result] = sender.send(make_event())
    assert result["event"]["id"] >= 1 and not sender.queue


def test_agent_refuses_an_untrusted_certificate_and_keeps_the_event(https_server, tmp_path, capsys):
    url, _ = https_server
    sender = Sender(url, None, tmp_path / "spool.jsonl")  # no CA bundle: the self-signed CA is not trusted
    assert sender.send(make_event()) == []
    assert len(sender.queue) == 1 and "certificate not trusted" in capsys.readouterr().out


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1_1 is deprecated:DeprecationWarning")
def test_tls_handshake_rejects_tls_1_1(https_server):
    import ssl

    url, ca = https_server
    port = int(url.rsplit(":", 1)[1])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(ca))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    with pytest.raises(ssl.SSLError):
        with socket.create_connection(("127.0.0.1", port)) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost"):
                pass
    ok = requests.get(f"{url}/health", verify=str(ca), timeout=5)
    assert ok.json() == {"status": "ok"}


def test_agent_warns_about_plain_http_to_other_machines():
    assert plaintext_risk("http://192.168.1.20:8000")
    assert not plaintext_risk("http://localhost:8000") and not plaintext_risk("https://192.168.1.20:8000")


def test_security_status_reports_plain_http(client):
    body = client.get("/system/security").json()
    assert body["tls"]["enabled"] is False and any("plain HTTP" in w for w in body["warnings"])
