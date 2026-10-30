"""Verify a TraceForge forensic report or attestation offline, without the server.

    python tools/verify_signature.py report.json report.json.sig --public-key traceforge_public.pem
    python tools/verify_signature.py --attestation attestation.json --public-key traceforge_public.pem

Needs only the `cryptography` package. Get the public key once from GET /signing/public-key
(or the dashboard's "Public key" link) and keep it with the case file; a verifier who trusts that
key can then check any report without contacting the server.

Exit code 0 = valid signature, 1 = invalid or the file was changed, 2 = usage error.
"""

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ALGORITHM = "RSA-PSS-SHA256"
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def load_public_key(path: Path):
    text = path.read_text()
    if text.lstrip().startswith("{"):  # the JSON from GET /signing/public-key, saved as-is
        text = json.loads(text)["public_key_pem"]
    return serialization.load_pem_public_key(text.encode())


def key_id(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def check(public_key, message: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64), message, PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", nargs="?", help="the exported report file")
    parser.add_argument("signature", nargs="?", help="its .sig file (JSON saved from the dashboard)")
    parser.add_argument("--attestation", help="a saved response of GET /integrity/attestation")
    parser.add_argument("--public-key", required=True, help="the server's public key: PEM, or the saved /signing/public-key JSON")
    args = parser.parse_args()

    public_key = load_public_key(Path(args.public_key))
    print(f"public key id: {key_id(public_key)}")

    if args.attestation:
        doc = json.loads(Path(args.attestation).read_text())
        statement = doc["statement"]
        message = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        ok = check(public_key, message, doc["signature"])
        print(f"attestation at {statement['attested_at']}: chain head {statement['chain_head']}, "
              f"{statement['events_checked']} events, intact={statement['intact']}")
        claimed_key = statement.get("key_id")
    elif args.report and args.signature:
        message = Path(args.report).read_bytes()
        sig = json.loads(Path(args.signature).read_text())
        if sig.get("algorithm") != ALGORITHM:
            print(f"unsupported algorithm {sig.get('algorithm')!r}")
            return 2
        digest = hashlib.sha256(message).hexdigest()
        if sig.get("sha256") and sig["sha256"] != digest:
            print(f"SHA-256 mismatch: the file is not the one that was signed\n  signed:  {sig['sha256']}\n  file:    {digest}")
        ok = check(public_key, message, sig["signature"])
        claimed_key = sig.get("key_id")
    else:
        parser.error("give a report and its .sig file, or --attestation")
        return 2

    if claimed_key and claimed_key != key_id(public_key):
        print(f"note: signed with key {claimed_key}, but this public key is {key_id(public_key)}")
    print("VALID: signed by this key and unchanged since." if ok else "INVALID: wrong key, or the content was changed after signing.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
