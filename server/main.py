import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server import integrity, models  # noqa: F401  (models registers tables on Base.metadata)
from server.config import settings
from server.database import Base, SessionLocal, engine, upgrade_schema
from server.routers import anomalies, audit_log, auth, devices, events, evidence, forensics, graph, incidents, risk, system
from server.scheduler import retrain_loop


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    upgrade_schema()
    with SessionLocal() as db:
        integrity.backfill(db)  # events stored before the evidence chain existed
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
    expose_headers=["X-Content-SHA256"],
)

for r in (events, devices, anomalies, risk, incidents, system, evidence, auth, audit_log, graph, forensics):
    app.include_router(r.router)


@app.get("/health")
def health():
    return {"status": "ok"}
