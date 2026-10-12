from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://traceforge:traceforge@localhost:5432/traceforge"
    # Shared secret agents send as X-API-Key. Unset disables the check (local development only).
    api_key: str | None = None
    # Production: store only the key's SHA-256 here instead (python -m server.manage hash-key).
    api_key_hash: str | None = None
    # Investigator logins and roles (see server/auth.py). Off for local development.
    auth_enabled: bool = False
    # Comma-separated origins allowed to call the API from a browser (the dashboard's address).
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    # Storage is always UTC; this zone defines "night" for the ML hour-of-day feature and the seeder.
    timezone: str = "Asia/Kolkata"
    # Behavioural model: Isolation Forest (default) or One-Class SVM.
    ml_algorithm: Literal["iforest", "ocsvm"] = "iforest"
    # Retrain the model on stored history every N hours; 0 turns scheduled retraining off.
    retrain_interval_hours: float = 0
    # A copy to a USB storage device this large is flagged (large_transfer), as is 10x its usual.
    exfil_threshold_mb: float = 500


settings = Settings()
