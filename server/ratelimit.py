"""Failed-login throttling (online password guessing, OWASP ASVS V2.2).

PBKDF2 at 600k iterations makes each guess slow, but nothing stopped an attacker from guessing
all day, and every guess costs the server a full hash. After LOGIN_MAX_FAILURES failures in the
window, further attempts for that username, or from that client address, get 429 without
hashing anything. Counted per username so one account cannot be guessed from many addresses,
and per address so one client cannot spray many usernames.

Kept in memory: it resets when the server restarts and is per process, which is fine for the
single-server deployment in docker-compose.yml; a multi-server deployment would keep it in the database.
"""

import threading
import time
from collections import defaultdict, deque

from server.config import settings

_failures: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def _window() -> float:
    return settings.login_window_minutes * 60


def _prune(key: str, now: float) -> deque[float]:
    q = _failures[key]
    while q and now - q[0] > _window():
        q.popleft()
    return q


def retry_after(*keys: str) -> int | None:
    """Seconds until a blocked key may try again, or None if none of the keys is blocked."""
    now = time.monotonic()
    with _lock:
        waits = []
        for key in keys:
            q = _prune(key, now)
            if len(q) >= settings.login_max_failures:
                waits.append(int(_window() - (now - q[0])) + 1)
        return max(waits) if waits else None


def failed(*keys: str) -> None:
    now = time.monotonic()
    with _lock:
        for key in keys:
            _prune(key, now).append(now)


def succeeded(username_key: str) -> None:
    with _lock:
        _failures.pop(username_key, None)


def reset() -> None:
    with _lock:
        _failures.clear()
