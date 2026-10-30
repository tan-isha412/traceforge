import asyncio
from pathlib import Path
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server import audit, integrity, models, signing, tls  # noqa: F401  (models registers tables on Base.metadata)
from server.config import settings
from server.database import Base, SessionLocal, engine, upgrade_schema
from server.routers import anomalies, audit_log, auth, devices, events, evidence, forensics, graph, incidents, risk, rules, signing as signing_router, system
from server.auth import current_user
from server.scheduler import retrain_loop
from server.security import agent_keys_configured, api_key_configured


log = logging.getLogger("traceforge")

INSECURE_KEYS = {"change-me", "changeme", "traceforge", "secret"}


def security_warnings() -> list[str]:
    """Settings fine for a demo and wrong for evidence anyone will rely on. Logged at startup and
    shown on GET /system/security so a deployment cannot be insecure without anybody noticing."""
    out = []
    if not settings.auth_enabled:
        out.append("AUTH_ENABLED=false: anyone who can reach the API can read every case and change incidents.")
    if not api_key_configured() and not agent_keys_configured():
        out.append("No API_KEY, API_KEY_HASH or AGENT_KEYS: anyone can post forged USB events.")
    elif (settings.api_key or "").strip().lower() in INSECURE_KEYS:
        out.append("API_KEY is a well-known placeholder; generate one with python -m server.manage hash-key.")
    if not agent_keys_configured():
        out.append("No AGENT_KEYS: every agent shares one key, so one compromised machine can report as any other.")
    if not (settings.tls_cert_file and settings.tls_key_file) and not settings.tls_terminated_by_proxy:
        out.append("Serving plain HTTP: API keys, passwords and evidence cross the network unencrypted. "
                   "Run python -m server.manage tls-init and set TLS_CERT_FILE / TLS_KEY_FILE.")
    if "traceforge:traceforge@" in settings.database_url:
        out.append("The database still uses the default traceforge/traceforge credentials.")
    return out


def tls_status() -> dict:
    if settings.tls_cert_file and settings.tls_key_file:
        try:
            return {"enabled": True, **tls.describe(Path(settings.tls_cert_file))}
        except (OSError, ValueError) as exc:
            return {"enabled": True, "error": str(exc)}
    return {"enabled": False, "terminated_by_proxy": settings.tls_terminated_by_proxy}


@asynccontextmanager
async def lifespan(_: FastAPI):
    for warning in security_warnings():
        log.warning("SECURITY: %s", warning)
    Base.metadata.create_all(bind=engine)
    upgrade_schema()
    with SessionLocal() as db:
        integrity.backfill(db)  # events stored before the evidence chain existed
        signing.private_key()  # load the signing key now, or create it, so a bad passphrase fails at startup
        if signing.was_created_now():
            audit.record(db, "system", "signing.key_created", key_id=signing.key_id(), algorithm=signing.ALGORITHM)
            db.commit()
        log.info("Signing key %s (%s)", signing.key_id(), signing.ALGORITHM)
    task = asyncio.create_task(retrain_loop()) if settings.retrain_interval_hours > 0 else None
    yield
    if task is not None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="TraceForge", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    expose_headers=["X-Content-SHA256", "X-Signature", "X-Signature-Algorithm", "X-Signature-Key-Id"],
)

for r in (events, devices, anomalies, risk, incidents, system, evidence, auth, audit_log, graph, forensics, rules, signing_router):
    app.include_router(r.router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/system/security", dependencies=[Depends(current_user)])
def security_status():
    """Which security settings are still at their development defaults (no secrets are returned)."""
    return {
        "auth_enabled": settings.auth_enabled,
        "agent_keys": agent_keys_configured(),
        "shared_key_allowed_for_ingest": not settings.require_agent_keys,
        "tls": tls_status(),
        "signing_key_id": signing.key_id(),
        "warnings": security_warnings(),
    }
