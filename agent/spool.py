"""Encryption for the agent's offline spool (events waiting for the server).

While the server is unreachable the agent keeps events in ~/.traceforge/spool.jsonl on the monitored
machine. In plaintext anyone with access to that machine could read which devices were plugged in, or,
worse, quietly edit or delete queued evidence before it reaches the server's hash chain (which only
protects events once they have arrived). Each line is therefore sealed with AES-256-GCM:

    key   = HKDF-SHA256(ikm = agent API key, salt = "traceforge-spool-v1", info = hostname)   32 bytes
    line  = "v1:" + base64( nonce (12 random bytes) || AES-256-GCM(key, nonce, event JSON, aad) )
    aad   = "traceforge-spool-v1"

GCM is authenticated encryption: confidentiality plus a 128-bit tag, so a line that was altered (or
sealed with another key) fails to open instead of decrypting to something wrong. Such lines are moved
to spool.jsonl.rejected for investigation, never sent and never silently dropped.

The key is derived from the agent's API key, which lives in the agent's environment, not on disk next
to the spool. HKDF turns that secret into a proper AES key, bound to this machine's hostname, so the
spool key is never the API key itself. With no API key (local development) the spool stays plaintext,
as there is no secret to derive a key from.
"""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = "v1"
_SALT = b"traceforge-spool-v1"
_AAD = b"traceforge-spool-v1"
NONCE_BYTES = 12  # 96-bit nonces: the size GCM is designed for; random per line


class SpoolCipher:
    def __init__(self, api_key: str | None, hostname: str):
        self._aead = None
        if api_key:
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SALT, info=hostname.encode()).derive(api_key.encode())
            self._aead = AESGCM(key)

    @property
    def encrypting(self) -> bool:
        return self._aead is not None

    def seal(self, payload: dict) -> str:
        data = json.dumps(payload).encode()
        if self._aead is None:
            return data.decode()
        nonce = os.urandom(NONCE_BYTES)
        return f"{VERSION}:" + base64.b64encode(nonce + self._aead.encrypt(nonce, data, _AAD)).decode()

    def open(self, line: str) -> dict:
        """The event in a spool line. Raises ValueError for a line that was altered, sealed with a
        different key, or is encrypted while this agent has no key."""
        line = line.strip()
        if line.startswith("{"):  # plaintext: spools written before encryption, or without an API key
            return json.loads(line)
        if not line.startswith(f"{VERSION}:"):
            raise ValueError("unrecognised spool line")
        if self._aead is None:
            raise ValueError("encrypted spool line, but this agent has no API key to decrypt it")
        raw = base64.b64decode(line[len(VERSION) + 1:])
        try:
            return json.loads(self._aead.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], _AAD))
        except InvalidTag as exc:
            raise ValueError("authentication failed: the line was modified, or sealed with a different API key") from exc
