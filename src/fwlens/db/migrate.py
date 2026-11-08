"""Run Alembic migrations from code (CLI and tests), not just the alembic command."""

from pathlib import Path

from alembic import command
from alembic.config import Config

# Repo root; alembic.ini and migrations/ live next to src/.
ALEMBIC_INI = Path(__file__).resolve().parents[3] / "alembic.ini"


def upgrade_schema(url: str | None = None) -> None:
    """Migrate the database at `url` (default: DATABASE_URL) to the latest revision."""
    config = Config(str(ALEMBIC_INI))
    if url:
        # Alembic config values use % interpolation; escape it in passwords.
        config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(config, "head")
