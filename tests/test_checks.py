"""Each check in checks.sql vs the ground truth in evals/cases/seeded_flaws.json.

A check that isn't written yet is skipped (not failed), so CI stays green while the
SQL is in progress. Once written, it must find exactly the expected rules.
"""

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from fwlens.analysis.checks import CHECK_NAMES, load_queries, run_check
from fwlens.db.load import load_config, load_log_file
from fwlens.db.schema import rules
from fwlens.parsers import parse_config_file

pytestmark = pytest.mark.db

ROOT = Path(__file__).parents[1]
TRUTH = json.loads((ROOT / "evals" / "cases" / "seeded_flaws.json").read_text(encoding="utf-8"))


@pytest.fixture
def loaded(conn):
    """The test database with every sample config and log loaded (rolled back after)."""
    for path in TRUTH["samples"]["configs"]:
        load_config(conn, parse_config_file(ROOT / path))
    for path in TRUTH["samples"]["logs"]:
        load_log_file(conn, ROOT / path)
    return conn


def test_ground_truth_covers_every_check() -> None:
    assert set(TRUTH["checks"]) == set(CHECK_NAMES)


def test_ground_truth_names_real_rules(loaded) -> None:
    """Guards the JSON itself against typos, even before any SQL is written."""
    rule_ids = set(loaded.execute(select(rules.c.id)).scalars())
    for check, expected in TRUTH["checks"].items():
        for item in expected:
            assert item["rule_id"] in rule_ids, (check, item["rule_id"])
            if item["related_rule_id"]:
                assert item["related_rule_id"] in rule_ids, (check, item["related_rule_id"])


@pytest.mark.parametrize("check", CHECK_NAMES)
def test_check_matches_ground_truth(loaded, check: str) -> None:
    query = load_queries()[check]
    if query is None:
        pytest.skip(f"checks.sql: {check} not written yet")

    findings = run_check(loaded, check, query)
    found = [(f.rule_id, f.related_rule_id) for f in findings]
    expected = {(i["rule_id"], i["related_rule_id"]) for i in TRUTH["checks"][check]}

    assert len(found) == len(set(found)), f"{check} reported a finding twice"
    missing = expected - set(found)
    extra = set(found) - expected
    assert not missing and not extra, f"{check}: missing {sorted(missing)}, extra {sorted(extra)}"

    details = {f.rule_id: f.detail for f in findings}
    for item in TRUTH["checks"][check]:
        assert details[item["rule_id"]].strip(), f"{check}: empty detail for {item['rule_id']}"
        if "detail_contains" in item:
            assert item["detail_contains"] in details[item["rule_id"]].lower(), (
                f"{check}: detail for {item['rule_id']} should mention {item['detail_contains']!r}"
            )
