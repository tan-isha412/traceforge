"""TLS certificates for a lab deployment: a private certificate authority and the server's certificate.

Agents send their API key and every USB event to the server, and investigators send passwords and
session tokens; on plain HTTP anyone on the network can read and replay them. TLS encrypts that
traffic and proves to the agent that it is talking to the real server. A lab has no public domain,
so TraceForge acts as its own small PKI:

    ca.crt / ca.key          the TraceForge root CA (self-signed). Agents and browsers trust ca.crt.
    server.crt / server.key  the server's certificate, signed by the CA, naming every hostname and IP
                             agents may use to reach it (subjectAltName).

Keys are ECDSA on P-256 (secp256r1) with SHA-256 signatures: 128-bit security with far smaller keys
and faster handshakes than RSA-3072. Server certificates last 397 days (the CA/Browser Forum limit
browsers enforce); re-running tls-init issues a new one from the same CA, so agents keep working.

    python -m server.manage tls-init --host traceforge-server --host 192.168.1.20
"""

import ipaddress
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 5 * 365
SERVER_DAYS = 397
CURVE = ec.SECP256R1()


@dataclass
class Issued:
    ca_cert: Path
    server_cert: Path
    server_key: Path
    hosts: list[str]
    ca_created: bool
    not_after: datetime


def default_hosts() -> list[str]:
    """Names agents commonly use: this machine, loopback, and the docker-compose service name."""
    return sorted({"localhost", "127.0.0.1", "::1", "server", socket.gethostname()})


def _write_private(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner-only
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _san(hosts: list[str]) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = []
    for h in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            names.append(x509.DNSName(h))
    return x509.SubjectAlternativeName(names)


def _create_ca(directory: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(CURVE)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TraceForge"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"TraceForge Local CA ({socket.gethostname()})"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_DAYS))
        # pathlen 0: this CA may sign server certificates but not other CAs.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    (directory / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(directory / "ca.key", key)
    return cert, key


def _load_ca(directory: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None:
    crt, key = directory / "ca.crt", directory / "ca.key"
    if not (crt.exists() and key.exists()):
        return None
    return x509.load_pem_x509_certificate(crt.read_bytes()), serialization.load_pem_private_key(key.read_bytes(), password=None)


def issue(directory: Path, hosts: list[str]) -> Issued:
    """Create the CA if there is none yet, then issue a fresh server certificate for `hosts`."""
    directory.mkdir(parents=True, exist_ok=True)
    loaded = _load_ca(directory)
    ca_created = loaded is None
    ca_cert, ca_key = loaded or _create_ca(directory)

    key = ec.generate_private_key(CURVE)
    now = datetime.now(timezone.utc)
    not_after = min(now + timedelta(days=SERVER_DAYS), ca_cert.not_valid_after_utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TraceForge"),
            x509.NameAttribute(NameOID.COMMON_NAME, hosts[0]),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(_san(hosts), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(directory / "server.key", key)
    return Issued(directory / "ca.crt", directory / "server.crt", directory / "server.key", hosts, ca_created, not_after)


def describe(cert_path: Path) -> dict:
    """What a certificate says, for the startup log and GET /system/security."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n.value) for n in san]
    except x509.ExtensionNotFound:
        names = []
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "names": names,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_left": (cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
    }
