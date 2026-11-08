"""Shared fixtures for tests that need a real Postgres.

Uses a separate fwlens_test database, dropped and re-created once per run. Each test
runs in a transaction that is rolled back, so tests don't see each other's data.
Skipped if Postgres is unreachable, unless FWLENS_REQUIRE_DB is set (CI).
"""

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from fwlens.db.migrate import upgrade_schema
from fwlens.db.session import CONNECT_TIMEOUT_SECONDS, get_engine

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://fwlens:fwlens@127.0.0.1:5432/fwlens_test"
)


@pytest.fixture(scope="session")
def engine():
    url = make_url(TEST_DATABASE_URL)
    admin = create_engine(
        url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",  # CREATE DATABASE can't run inside a transaction
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
    )
    try:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
            conn.execute(text(f'CREATE DATABASE "{url.database}"'))
    except OperationalError as exc:
        if os.environ.get("FWLENS_REQUIRE_DB"):
            raise
        pytest.skip(
            f"Postgres not reachable at {url.host}:{url.port} (docker compose up -d): {exc}"
        )
    finally:
        admin.dispose()

    url_string = url.render_as_string(hide_password=False)
    upgrade_schema(url_string)
    engine = get_engine(url_string)
    yield engine
    engine.dispose()


@pytest.fixture
def conn(engine):
    with engine.connect() as conn:
        transaction = conn.begin()
        yield conn
        transaction.rollback()
