from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://traceforge:traceforge@localhost:5432/traceforge"
    # Shared secret agents send as X-API-Key. Unset disables the check (local development only).
    api_key: str | None = None
    # Storage is always UTC; this zone defines "night" for the ML hour-of-day feature and the seeder.
    timezone: str = "Asia/Kolkata"


settings = Settings()
