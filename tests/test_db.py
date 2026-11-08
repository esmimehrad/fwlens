"""Integration tests against a real Postgres (arrays and inet don't exist in SQLite).

Uses a separate fwlens_test database, dropped and re-created once per run. Each test
runs in a transaction that is rolled back, so tests don't see each other's data.
"""

import os
from collections import Counter

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from fwlens.db.load import load_config, load_log_file
from fwlens.db.migrate import upgrade_schema
from fwlens.db.schema import log_events, log_files, metadata, rules
from fwlens.db.session import CONNECT_TIMEOUT_SECONDS, get_engine
from fwlens.models import Rule
from fwlens.parsers import parse_config_file
from fwlens.samplegen import NO_TRAFFIC, SAMPLES

pytestmark = pytest.mark.db

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://fwlens:fwlens@127.0.0.1:5432/fwlens_test"
)
PANOS = SAMPLES / "panos" / "lab-fw01.xml"
FORTI = SAMPLES / "fortigate" / "lab-fgt01.conf"
PANOS_LOG = SAMPLES / "logs" / "lab-fw01.log"


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


def count(conn, table, *where) -> int:
    return conn.execute(select(func.count()).select_from(table).where(*where)).scalar_one()


# --- schema ------------------------------------------------------------------------


def test_migrations_match_schema_py(conn) -> None:
    """The hand-written migration and schema.py describe the same database."""
    diff = compare_metadata(MigrationContext.configure(conn), metadata)
    assert diff == []


# --- configs -----------------------------------------------------------------------


@pytest.mark.parametrize("path", [PANOS, FORTI], ids=["panos", "fortigate"])
def test_config_round_trip(conn, path) -> None:
    config = parse_config_file(path)
    load_config(conn, config)

    stored = conn.execute(
        select(rules).where(rules.c.device == config.device).order_by(rules.c.position)
    ).mappings()
    # Rebuild models from rows; `id` is computed by the model, so leave it out.
    assert [Rule(**{k: v for k, v in row.items() if k != "id"}) for row in stored] == list(
        config.rules
    )


def test_reload_replaces_the_device(conn) -> None:
    config = parse_config_file(PANOS)
    load_config(conn, config)
    smaller = config.model_copy(update={"rules": config.rules[:3]})
    load_config(conn, smaller)
    assert count(conn, rules, rules.c.device == "lab-fw01") == 3


def test_any_any_query_uses_arrays(conn) -> None:
    load_config(conn, parse_config_file(PANOS))
    names = conn.execute(
        text(
            "SELECT name FROM rules WHERE action = 'allow' "
            "AND 'any' = ANY(src_addrs) AND 'any' = ANY(dst_addrs) AND 'any' = ANY(services)"
        )
    ).scalars()
    assert list(names) == ["temp-vendor-access"]


# --- logs --------------------------------------------------------------------------


def test_log_load_is_idempotent(conn) -> None:
    assert load_log_file(conn, PANOS_LOG) == 1000
    assert load_log_file(conn, PANOS_LOG) is None  # same sha256: skipped
    assert count(conn, log_events) == 1000


def test_hit_counts_match_generator_ground_truth(conn) -> None:
    config = parse_config_file(PANOS)
    load_config(conn, config)
    load_log_file(conn, PANOS_LOG)
    hits = Counter(
        dict(
            conn.execute(
                select(log_events.c.rule_name, func.count()).group_by(log_events.c.rule_name)
            ).all()
        )
    )
    for rule in config.rules:
        silent = not rule.enabled or not rule.log or rule.name in NO_TRAFFIC
        assert (hits[rule.name] == 0) == silent, rule.name


def test_inet_containment(conn) -> None:
    load_log_file(conn, PANOS_LOG)
    in_users = conn.execute(
        text("SELECT count(*) FROM log_events WHERE src_ip << '10.10.10.0/24'::cidr")
    ).scalar_one()
    assert 0 < in_users < 1000


def test_deleting_a_log_file_unloads_its_events(conn) -> None:
    load_log_file(conn, PANOS_LOG)
    conn.execute(log_files.delete())
    assert count(conn, log_events) == 0
