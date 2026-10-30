from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://traceforge:traceforge@localhost:5432/traceforge"
    # Shared secret agents send as X-API-Key. Unset disables the check (local development only).
    api_key: str | None = None
    # Production: store only the key's SHA-256 here instead (python -m server.manage hash-key).
    api_key_hash: str | None = None
    # Per-agent keys, each bound to the one hostname it may report for: "HOST=sha256hex,HOST2=sha256hex"
    # (python -m server.manage agent-key HOST prints a line). Stops one compromised machine from
    # forging events for every other machine with the shared key.
    agent_keys: str | None = None
    # With per-agent keys in place, refuse the shared API_KEY on /events/ingest altogether.
    require_agent_keys: bool = False
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
    # HTTPS: the server certificate and key from `python -m server.manage tls-init` (served by server/run.py).
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    # Set when a reverse proxy in front of the server terminates TLS instead (silences the plain-HTTP warning).
    tls_terminated_by_proxy: bool = False
    # Digital signatures on exports and attestations (server/signing.py). Empty path = server/model_artifacts/signing_key.pem.
    signing_key_path: str | None = None
    # When set, the private key file is stored encrypted with this passphrase.
    signing_key_passphrase: str | None = None
    # Failed logins allowed per username (and per client address) in the window before /auth/login returns 429.
    login_max_failures: int = 5
    login_window_minutes: float = 15
    # Where the trained model is saved; give real data its own file so the demo model is kept.
    model_path: str | None = None


settings = Settings()
