"""Digital signatures for evidence leaving the server (forensic exports, chain-head attestations).

A SHA-256 hash proves a file is unchanged, but anyone can recompute a hash: it does not say who
produced the file. A digital signature does. The server holds an RSA-2048 private key and signs
with RSA-PSS over SHA-256; anyone holding the public key (GET /signing/public-key) can check that
a report came from this TraceForge server and was not altered since (authenticity, integrity and
non-repudiation, on top of the hash chain's integrity).

    signature = RSA-PSS-Sign(private_key, SHA-256(message))     MGF1-SHA-256, salt = 32 bytes

PSS rather than PKCS#1 v1.5 because it is the scheme with a security proof and the one current
guidance recommends for new systems; the 32-byte salt keeps it verifiable by browsers (WebCrypto).

The key pair is created on first use and kept at SIGNING_KEY_PATH (in the model volume under
Docker, so it survives restarts), readable by its owner only. With SIGNING_KEY_PASSPHRASE set, the
private key file is stored encrypted as PKCS#8 PBES2: the passphrase goes through PBKDF2-HMAC-SHA256
(salted, iterated) to derive an AES-256 key, and the private key is encrypted with AES-256-CBC, so a
copied key file alone is useless.
The key id is the first 16 hex characters of SHA-256(public key, DER), printed with every signature
so a verifier can tell which key to use after a key change.
"""

import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from server.config import settings

ALGORITHM = "RSA-PSS-SHA256"
KEY_BITS = 2048
PUBLIC_EXPONENT = 65537  # 0x10001, as in the lab's RSA signature exercise
SALT_LENGTH = 32  # = SHA-256 digest length; WebCrypto needs the salt length stated explicitly
DEFAULT_PATH = Path(__file__).resolve().parent / "model_artifacts" / "signing_key.pem"

_lock = threading.Lock()
_key: rsa.RSAPrivateKey | None = None
_created_now = False


def key_path() -> Path:
    return Path(settings.signing_key_path) if settings.signing_key_path else DEFAULT_PATH


def _passphrase() -> bytes | None:
    return settings.signing_key_passphrase.encode() if settings.signing_key_passphrase else None


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LENGTH)


def private_key() -> rsa.RSAPrivateKey:
    """The server's signing key, created and saved on first use."""
    global _key, _created_now
    with _lock:
        if _key is not None:
            return _key
        path = key_path()
        if path.exists():
            try:
                _key = serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Cannot load the signing key at {path}: wrong or missing SIGNING_KEY_PASSPHRASE ({exc})."
                ) from exc
        else:
            _key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_BITS)
            secret = _passphrase()
            encryption = serialization.BestAvailableEncryption(secret) if secret else serialization.NoEncryption()
            pem = _key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Owner read/write only: the private key is the one secret that makes signatures mean anything.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            _created_now = True
        return _key


def was_created_now() -> bool:
    """True once, after this process generated a new key (for the audit log)."""
    global _created_now
    created, _created_now = _created_now, False
    return created


def public_key_pem() -> str:
    return private_key().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def key_id() -> str:
    der = private_key().public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def sign(message: bytes) -> str:
    """Base64 RSA-PSS signature of the message."""
    return base64.b64encode(private_key().sign(message, _pss(), hashes.SHA256())).decode()


def verify(message: bytes, signature_b64: str, public_pem: str | None = None) -> bool:
    """Check a signature against this server's key, or against the given public key PEM."""
    key = serialization.load_pem_public_key(public_pem.encode()) if public_pem else private_key().public_key()
    try:
        key.verify(base64.b64decode(signature_b64), message, _pss(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def signature_record(message: bytes) -> dict:
    """Everything a verifier needs besides the message itself (the content of a .sig file)."""
    return {
        "algorithm": ALGORITHM,
        "key_id": key_id(),
        "sha256": hashlib.sha256(message).hexdigest(),
        "signature": sign(message),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def canonical(data: dict) -> bytes:
    """The exact bytes a JSON statement is signed over: sorted keys, no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
