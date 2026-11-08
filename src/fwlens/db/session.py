"""Database connection settings.

DATABASE_URL comes from the environment; the default points at the local
docker compose database, so a fresh clone works without any configuration.
"""

import os

from sqlalchemy import Engine, create_engine

# 127.0.0.1, not "localhost": on Windows "localhost" tries IPv6 ::1 first, and the
# compose port is bound to IPv4 only, so the connection hangs instead of failing.
DEFAULT_DATABASE_URL = "postgresql+psycopg://fwlens:fwlens@127.0.0.1:5432/fwlens"
CONNECT_TIMEOUT_SECONDS = 5


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_engine(url: str | None = None) -> Engine:
    return create_engine(
        url or database_url(),
        pool_pre_ping=True,  # reconnect cleanly if the database restarted under us
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},  # fail fast if it's down
    )
