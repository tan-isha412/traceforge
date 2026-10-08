from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from server.config import settings


def as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def local_tz() -> ZoneInfo:
    return ZoneInfo(settings.timezone)


def to_local(dt: datetime) -> datetime:
    return as_utc(dt).astimezone(local_tz())
