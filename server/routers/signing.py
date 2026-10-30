from fastapi import APIRouter

from server import signing

# Public on purpose: a public key is meant to be handed to anyone who needs to verify a report,
# including people with no TraceForge login (a court, another lab, the device owner).
router = APIRouter(prefix="/signing", tags=["signing"])


@router.get("/public-key")
def public_key():
    """The server's RSA public key (PEM) and key id, for verifying signed reports and attestations."""
    return {
        "algorithm": signing.ALGORITHM,
        "key_id": signing.key_id(),
        "key_bits": signing.KEY_BITS,
        "public_exponent": signing.PUBLIC_EXPONENT,
        "salt_length": signing.SALT_LENGTH,
        "public_key_pem": signing.public_key_pem(),
    }
