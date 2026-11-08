"""Alembic environment: where migrations get their connection and target schema."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection

from fwlens.db.schema import metadata
from fwlens.db.session import database_url, get_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The current schema, used by `alembic check` / autogenerate to detect drift.
target_metadata = metadata


def url() -> str:
    # A URL set programmatically (tests point at fwlens_test) wins over DATABASE_URL.
    return config.get_main_option("sqlalchemy.url") or database_url()


def run_migrations_offline() -> None:
    """`alembic upgrade --sql`: print the SQL instead of running it."""
    context.configure(url=url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Callers (tests, the CLI) can hand over an open connection instead of a URL.
    connection = config.attributes.get("connection")
    if connection is not None:
        run(connection)
        return
    with get_engine(url()).connect() as connection:
        run(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
