"""Start the API server, over HTTPS when TLS_CERT_FILE and TLS_KEY_FILE are set.

    python -m server.run                    (what the Docker image runs)

For development, `uvicorn server.main:app --reload` still works and serves plain HTTP.
Python's server-side TLS context accepts TLS 1.2 and 1.3 only (no SSLv3 / TLS 1.0 / 1.1) with
its default modern cipher list, so no extra cipher configuration is needed here.
"""

import os

import uvicorn

from server.config import settings


def main() -> None:
    tls = bool(settings.tls_cert_file and settings.tls_key_file)
    uvicorn.run(
        "server.main:app",
        host=os.environ.get("TRACEFORGE_HOST", "0.0.0.0"),
        port=int(os.environ.get("TRACEFORGE_PORT", "8000")),
        ssl_certfile=settings.tls_cert_file if tls else None,
        ssl_keyfile=settings.tls_key_file if tls else None,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
