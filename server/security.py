"""Machine-client checks (agents, scripts) on endpoints that change state.

Two kinds of agent credential:
  shared key  API_KEY / API_KEY_HASH, one secret for every agent (simple; any holder can claim any hostname)
  agent keys  AGENT_KEYS, one key per machine, accepted only for events naming that machine
"""

import hashlib
import hmac

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from server.auth import current_user
from server.config import settings
from server.database import get_db
from server.models import User


def api_key_configured() -> bool:
    return bool(settings.api_key_hash or settings.api_key)


def api_key_valid(x_api_key: str | None) -> bool:
    if x_api_key is None:
        return False
    if settings.api_key_hash:  # only the key's SHA-256 is stored on the server
        return hmac.compare_digest(hashlib.sha256(x_api_key.encode()).hexdigest(), settings.api_key_hash.strip().lower())
    return hmac.compare_digest(x_api_key.encode(), settings.api_key.encode())


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """No-op when no key is configured (local development); otherwise X-API-Key must match."""
    if api_key_configured() and not api_key_valid(x_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")


def admin_or_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> str:
    """For admin actions a script may also run (retraining): a valid API key, or an admin login.
    Returns who did it, for the audit log."""
    if api_key_configured() and api_key_valid(x_api_key):
        return "api-key"
    if settings.auth_enabled:
        user: User | None = current_user(authorization, db)
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="This needs the admin role.")
        return user.username
    if api_key_configured():
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")
    return "anonymous"



def _agent_key_table() -> dict[str, str]:
    """sha256(key) -> hostname (lower-case), from AGENT_KEYS="HOST=sha256hex,..."."""
    table = {}
    for item in (settings.agent_keys or "").split(","):
        if not item.strip():
            continue
        host, _, digest = item.strip().rpartition("=")
        if host and len(digest) == 64:
            table[digest.strip().lower()] = host.strip().lower()
    return table


def agent_keys_configured() -> bool:
    return bool(_agent_key_table())


def authorize_agent(x_api_key: str | None, hostname: str) -> str | None:
    """Who is reporting an event for `hostname`: "agent:<host>", "shared-key", or None in open
    development mode. Raises 401 for a missing or wrong key and 403 for a key bound to another machine."""
    table = _agent_key_table()
    if x_api_key is not None and table:
        bound = table.get(hashlib.sha256(x_api_key.encode()).hexdigest())
        if bound is not None:
            if bound != hostname.strip().lower():
                raise HTTPException(status_code=403, detail=f"This agent key may only report events for {bound}.")
            return f"agent:{bound}"
    if api_key_configured() and api_key_valid(x_api_key):
        if settings.require_agent_keys:
            raise HTTPException(status_code=403, detail="The shared API key is disabled for ingest; use this machine's agent key.")
        return "shared-key"
    if api_key_configured() or table:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")
    return None
