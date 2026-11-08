"""Run the rule checks in checks.sql.

checks.sql holds one query per check under a "-- name: <check>" line. This module splits
the file, runs each query, enforces the column contract, and returns Findings.
A check whose body is only comments/whitespace is "not written yet" and is skipped.
"""

import logging
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Connection, text

log = logging.getLogger(__name__)

CHECKS_SQL = Path(__file__).with_name("checks.sql")
CHECK_NAMES = ("any_any", "logging_off", "duplicate", "shadowed", "zero_hit")
COLUMNS = ("rule_id", "related_rule_id", "detail")

_NAME_LINE = re.compile(r"^--\s*name:\s*(\w+)\s*$", re.MULTILINE)


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    check: str
    rule_id: str
    related_rule_id: str | None
    detail: str


def load_queries(sql: str | None = None) -> dict[str, str | None]:
    """{check name: query}, with None for checks that aren't written yet."""
    if sql is None:
        sql = CHECKS_SQL.read_text(encoding="utf-8")
    parts = _NAME_LINE.split(sql)  # [preamble, name1, body1, name2, body2, ...]
    queries: dict[str, str | None] = {}
    for name, body in zip(parts[1::2], parts[2::2], strict=True):
        if name in queries:
            raise ValueError(f"checks.sql: check {name!r} is defined twice")
        if name not in CHECK_NAMES:
            raise ValueError(f"checks.sql: unknown check {name!r}; expected one of {CHECK_NAMES}")
        query = body.strip().rstrip(";").strip()
        queries[name] = query if _has_sql(query) else None
    missing = set(CHECK_NAMES) - set(queries)
    if missing:
        raise ValueError(f"checks.sql: missing sections for {sorted(missing)}")
    return queries


def _has_sql(query: str) -> bool:
    return any(line.strip() and not line.strip().startswith("--") for line in query.splitlines())


def run_check(conn: Connection, name: str, query: str) -> list[Finding]:
    result = conn.execute(text(query))
    columns = tuple(result.keys())
    if columns != COLUMNS:
        raise ValueError(f"check {name!r} returned columns {columns}, expected {COLUMNS}")
    return [Finding(check=name, **row) for row in result.mappings()]


def run_checks(conn: Connection, names: list[str] | None = None) -> list[Finding]:
    """Run the written checks (all, or just `names`); unwritten ones are skipped with a log."""
    queries = load_queries()
    findings = []
    for name in names or CHECK_NAMES:
        query = queries[name]
        if query is None:
            log.info("check %s: not written yet, skipped", name)
            continue
        findings += run_check(conn, name, query)
    return findings
