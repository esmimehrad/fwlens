"""Edge cases for checks.sql that the sample configs don't exercise.

Each test loads a tiny hand-built config and asserts what one check reports.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import insert

from fwlens.analysis.checks import load_queries, run_check
from fwlens.db.load import load_config
from fwlens.db.schema import log_events, log_files
from fwlens.models import ANY, AddressKind, AddressObject, ParsedConfig, Rule, ServiceObject
from fwlens.parsers.resolve import resolve_addresses, resolve_services

pytestmark = pytest.mark.db

DEVICE = "edge-fw"


def rule(name: str, position: int, **fields) -> Rule:
    defaults = {
        "src_zones": ("trust",),
        "dst_zones": ("untrust",),
        "src_addrs": (ANY,),
        "dst_addrs": (ANY,),
        "services": (ANY,),
        "applications": (ANY,),
        "action": "allow",
    }
    return Rule(vendor="panos", device=DEVICE, name=name, position=position, **defaults | fields)


def address(name: str, value: str, kind: AddressKind = AddressKind.NETMASK) -> AddressObject:
    return AddressObject(vendor="panos", device=DEVICE, name=name, kind=kind, value=value)


def group(name: str, *members: str) -> AddressObject:
    return AddressObject(
        vendor="panos", device=DEVICE, name=name, kind=AddressKind.GROUP, members=members
    )


def service(name: str, *entries: str) -> ServiceObject:
    return ServiceObject(vendor="panos", device=DEVICE, name=name, entries=entries)


def findings(conn, check: str, rules, addresses=(), services=()) -> set[tuple[str, str | None]]:
    config = ParsedConfig(
        vendor="panos",
        device=DEVICE,
        rules=tuple(rules),
        addresses=resolve_addresses(addresses),
        services=resolve_services(services),
    )
    load_config(conn, config)
    return {
        (f.rule_id.split(":")[-1], f.related_rule_id and f.related_rule_id.split(":")[-1])
        for f in run_check(conn, check, load_queries()[check])
    }


# --- shadowed ----------------------------------------------------------------------


def test_host_inside_earlier_subnet_is_shadowed(conn) -> None:
    result = findings(
        conn,
        "shadowed",
        [rule("net", 1, dst_addrs=("lan",)), rule("host", 2, dst_addrs=("h1",))],
        addresses=[address("lan", "10.0.0.0/24"), address("h1", "10.0.0.7/32")],
    )
    assert result == {("host", "net")}


def test_broader_later_rule_is_not_shadowed(conn) -> None:
    result = findings(
        conn,
        "shadowed",
        [rule("host", 1, dst_addrs=("h1",)), rule("net", 2, dst_addrs=("lan",))],
        addresses=[address("lan", "10.0.0.0/24"), address("h1", "10.0.0.7/32")],
    )
    assert result == set()


def test_specific_values_never_cover_any(conn) -> None:
    result = findings(
        conn,
        "shadowed",
        [rule("web", 1, services=("https",)), rule("all", 2)],
        services=[service("https", "tcp/443")],
    )
    assert result == set()


def test_disabled_earlier_rule_does_not_shadow(conn) -> None:
    result = findings(conn, "shadowed", [rule("off", 1, enabled=False), rule("later", 2)])
    assert result == set()


def test_unresolved_member_keeps_rule_from_being_covered(conn) -> None:
    # "g" resolves to 10.0.0.7 plus a member that no longer exists: we can't prove the
    # earlier /24 covers the missing one, so it is not reported as shadowed.
    result = findings(
        conn,
        "shadowed",
        [rule("net", 1, dst_addrs=("lan",)), rule("grp", 2, dst_addrs=("g",))],
        addresses=[
            address("lan", "10.0.0.0/24"),
            address("h1", "10.0.0.7/32"),
            group("g", "h1", "ghost"),
        ],
    )
    assert result == set()


def test_fqdn_and_range_values_do_not_break_the_inet_cast(conn) -> None:
    result = findings(
        conn,
        "shadowed",
        [rule("names", 1, dst_addrs=("f", "r")), rule("same-fqdn", 2, dst_addrs=("f",))],
        addresses=[
            address("f", "cafe.example.com", AddressKind.FQDN),
            address("r", "10.0.0.1-10.0.0.9", AddressKind.RANGE),
        ],
    )
    assert result == {("same-fqdn", "names")}


def test_host_bits_in_netmask_value_are_handled(conn) -> None:
    # PAN-OS accepts "10.0.0.5/24" as an ip-netmask; inet (unlike cidr) allows host bits.
    result = findings(
        conn,
        "shadowed",
        [rule("net", 1, dst_addrs=("lan",)), rule("host", 2, dst_addrs=("h1",))],
        addresses=[address("lan", "10.0.0.5/24"), address("h1", "10.0.0.7/32")],
    )
    assert result == {("host", "net")}


def test_service_subset_is_shadowed_but_other_port_is_not(conn) -> None:
    result = findings(
        conn,
        "shadowed",
        [
            rule("web", 1, services=("sg",)),
            rule("https", 2, services=("s443",)),
            rule("ssh", 3, services=("s22",)),
        ],
        services=[
            service("s443", "tcp/443"),
            service("s80", "tcp/80"),
            service("s22", "tcp/22"),
            ServiceObject(
                vendor="panos", device=DEVICE, name="sg", is_group=True, members=("s80", "s443")
            ),
        ],
    )
    assert result == {("https", "web")}


def test_reports_the_earliest_covering_rule(conn) -> None:
    result = findings(
        conn,
        "shadowed",
        [
            rule("first", 1),
            rule("second", 2, dst_zones=("dmz", "untrust")),
            rule("narrow", 3, src_addrs=("h1",)),
        ],
        addresses=[address("h1", "10.0.0.7/32")],
    )
    assert ("narrow", "first") in result


def test_exact_duplicates_are_left_to_the_duplicate_check(conn) -> None:
    result = findings(conn, "shadowed", [rule("a", 1), rule("a-copy", 2)])
    assert result == set()


# --- duplicate ---------------------------------------------------------------------


def test_duplicate_ignores_value_order(conn) -> None:
    result = findings(
        conn,
        "duplicate",
        [rule("a", 1, src_zones=("x", "y")), rule("b", 2, src_zones=("y", "x"))],
    )
    assert result == {("b", "a")}


def test_three_copies_all_point_at_the_original(conn) -> None:
    result = findings(conn, "duplicate", [rule("a", 1), rule("b", 2), rule("c", 3)])
    assert result == {("b", "a"), ("c", "a")}


def test_subset_is_not_a_duplicate(conn) -> None:
    result = findings(
        conn,
        "duplicate",
        [rule("a", 1, src_zones=("x", "y")), rule("b", 2, src_zones=("x",))],
    )
    assert result == set()


# --- any_any / logging_off ---------------------------------------------------------


def test_any_any_ignores_deny_and_disabled(conn) -> None:
    result = findings(
        conn,
        "any_any",
        [rule("open", 1), rule("block", 2, action="deny"), rule("off", 3, enabled=False)],
    )
    assert result == {("open", None)}


def test_logging_off_ignores_deny_rules(conn) -> None:
    result = findings(
        conn,
        "logging_off",
        [rule("quiet-allow", 1, log=False), rule("quiet-deny", 2, action="deny", log=False)],
    )
    assert result == {("quiet-allow", None)}


# --- zero_hit ----------------------------------------------------------------------


def test_zero_hit_skips_devices_without_logs(conn) -> None:
    assert findings(conn, "zero_hit", [rule("a", 1)]) == set()


def test_zero_hit_with_logs(conn) -> None:
    conn.execute(insert(log_files).values(sha256="x", path="x.log", events=1))
    conn.execute(
        insert(log_events).values(
            log_file="x",
            vendor="panos",
            device=DEVICE,
            ts=datetime(2026, 11, 1, tzinfo=UTC),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port=443,
            protocol="tcp",
            rule_name="used",
            action="allow",
            bytes=100,
        )
    )
    result = findings(conn, "zero_hit", [rule("used", 1), rule("unused", 2)])
    assert result == {("unused", None)}
