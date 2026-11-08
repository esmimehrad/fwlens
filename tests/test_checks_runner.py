"""The checks.sql runner itself (no database needed except the last test)."""

import pytest

from fwlens.analysis.checks import CHECK_NAMES, load_queries, run_check

SECTIONS = "".join(f"-- name: {name}\n-- spec comment only\n\n" for name in CHECK_NAMES)


def test_committed_checks_sql_parses() -> None:
    assert set(load_queries()) == set(CHECK_NAMES)


def test_comment_only_body_means_not_written() -> None:
    assert load_queries(SECTIONS) == dict.fromkeys(CHECK_NAMES)


def test_written_query_is_kept_without_trailing_semicolon() -> None:
    sql = SECTIONS.replace(
        "-- name: any_any\n-- spec comment only\n",
        "-- name: any_any\n-- spec\nSELECT 1;\n",
    )
    assert load_queries(sql)["any_any"] == "-- spec\nSELECT 1"


def test_duplicate_section_raises() -> None:
    with pytest.raises(ValueError, match="defined twice"):
        load_queries(SECTIONS + "-- name: any_any\n")


def test_unknown_section_raises() -> None:
    with pytest.raises(ValueError, match="unknown check 'typo'"):
        load_queries(SECTIONS + "-- name: typo\n")


def test_missing_section_raises() -> None:
    with pytest.raises(ValueError, match="missing sections"):
        load_queries("-- name: any_any\n")


@pytest.mark.db
def test_wrong_columns_raise(conn) -> None:
    with pytest.raises(ValueError, match="expected \\('rule_id', 'related_rule_id', 'detail'\\)"):
        run_check(conn, "any_any", "SELECT 'x' AS rule_id, 'y' AS detail")


@pytest.mark.db
def test_rows_become_findings(conn) -> None:
    [finding] = run_check(
        conn, "any_any", "SELECT 'a:b:c' AS rule_id, NULL AS related_rule_id, 'why' AS detail"
    )
    assert (finding.check, finding.rule_id, finding.related_rule_id) == ("any_any", "a:b:c", None)
