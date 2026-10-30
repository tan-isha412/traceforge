from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from server import integrity, signing
from server.auth import current_user
from server.database import get_db
from server.schemas import IntegrityOut

router = APIRouter(prefix="/integrity", tags=["evidence"], dependencies=[Depends(current_user)])


@router.get("/verify", response_model=IntegrityOut)
def verify(db: Session = Depends(get_db)):
    """Recompute the evidence hash chain and report whether any stored event was altered."""
    return integrity.verify(db)


@router.get("/attestation")
def attestation(db: Session = Depends(get_db)):
    """A signed statement of the evidence chain's state right now.

    Keep it (or print it into a case file): later, anyone with the server's public key can check
    the signature, and a chain whose head no longer matches proves events were removed or changed
    after this moment, even the newest ones, which the hash chain alone cannot show."""
    state = integrity.verify(db)
    statement = {
        "statement": "TraceForge evidence chain state",
        "chain_head": state["chain_head"],
        "events_checked": state["events_checked"],
        "intact": state["intact"],
        "attested_at": datetime.now(timezone.utc).isoformat(),
        "key_id": signing.key_id(),
    }
    return {
        "statement": statement,
        "algorithm": signing.ALGORITHM,
        "signed_bytes": "canonical JSON of statement (sorted keys, no whitespace)",
        "signature": signing.sign(signing.canonical(statement)),
    }
