from pathlib import Path

import pytest

from fwlens.models import ANY, Action, AddressKind, Vendor
from fwlens.parsers.fortigate import parse_fortigate_file, parse_fortigate_text

SAMPLE = Path(__file__).parents[1] / "data" / "samples" / "fortigate" / "lab-fgt01.conf"


@pytest.fixture(scope="module")
def config():
    return parse_fortigate_file(SAMPLE)


@pytest.fixture(scope="module")
def rules(config):
    return {r.name: r for r in config.rules}


@pytest.fixture(scope="module")
def addresses(config):
    return {a.name: a for a in config.addresses}


@pytest.fixture(scope="module")
def services(config):
    return {s.name: s for s in config.services}


# --- sample config ---------------------------------------------------------


def test_device_and_vendor(config) -> None:
    assert config.vendor is Vendor.FORTIGATE
    assert config.device == "lab-fgt01"


def test_position_follows_config_order_not_policy_id(config) -> None:
    assert [r.name for r in config.rules] == [
        "allow-dns",
        "allow-web-out",
        "allow-web-in",
        "allow-ssh-admins",
        "allow-ssh-jump",
        "allow-ntp",
        "allow-web-out-copy",
        "old-ftp-access",
        "temp-vendor-access",  # policy 12, written before 10 and 11
        "deny-blocklist",
        "11",  # no `set name`: falls back to the policy ID
    ]
    assert [r.position for r in config.rules] == list(range(1, 12))


def test_rule_fields_are_mapped(rules) -> None:
    rule = rules["allow-web-in"]
    assert rule.id == "fortigate:lab-fgt01:allow-web-in"
    assert rule.src_zones == ("wan1",)
    assert rule.dst_zones == ("dmz",)
    assert rule.src_addrs == (ANY,)  # "all" normalized
    assert rule.dst_addrs == ("grp-web",)
    assert rule.services == ("sg-web",)
    assert rule.applications == (ANY,)
    assert rule.action is Action.ALLOW
    assert rule.enabled is True
    assert rule.log is True


def test_seeded_flaws_are_visible(rules) -> None:
    assert rules["allow-ntp"].log is False
    assert rules["old-ftp-access"].enabled is False
    any_any = rules["temp-vendor-access"]
    assert (any_any.src_addrs, any_any.dst_addrs, any_any.services) == ((ANY,), (ANY,), (ANY,))


def test_missing_action_defaults_to_deny(rules) -> None:
    assert rules["deny-blocklist"].action is Action.DENY


def test_subnet_mask_becomes_cidr(addresses) -> None:
    assert addresses["net-users"].value == "10.20.10.0/24"
    assert addresses["h-web01"].value == "10.20.20.11/32"
    assert addresses["all"].value == "0.0.0.0/0"  # no `set subnet`


def test_range_and_fqdn_addresses(addresses) -> None:
    assert addresses["r-bad-range"].kind is AddressKind.RANGE
    assert addresses["r-bad-range"].value == "198.51.100.10-198.51.100.20"
    assert addresses["f-bad-domain"].value == "bad.example.org"


def test_address_groups_resolve(addresses) -> None:
    assert addresses["grp-web"].resolved == ("10.20.20.11/32", "10.20.20.12/32")
    assert addresses["grp-blocklist"].unresolved == ("h-decom",)


def test_services(services) -> None:
    assert services["DNS"].entries == ("tcp/53", "udp/53")
    assert services["PING"].entries == ("icmp",)
    assert services["sg-web"].resolved == ("tcp/443", "tcp/8443")


# --- edge cases (inline config) --------------------------------------------


def make_conf(policy_body: str = "", extra: str = "") -> str:
    return f"""
config system global
    set hostname "t-fgt"
end
{extra}
config firewall policy
    edit 1
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        {policy_body}
    next
end
"""


def test_source_port_part_of_range_is_dropped() -> None:
    extra = 'config firewall service custom\nedit "web"\nset tcp-portrange 80:1024-65535\nnext\nend'
    config = parse_fortigate_text(make_conf(extra=extra))
    assert config.services[0].entries == ("tcp/80",)


def test_negated_source_raises() -> None:
    with pytest.raises(ValueError, match="srcaddr-negate"):
        parse_fortigate_text(make_conf("set srcaddr-negate enable"))


def test_unknown_action_raises() -> None:
    with pytest.raises(ValueError, match="unknown action 'ipsec'"):
        parse_fortigate_text(make_conf("set action ipsec"))


def test_unsupported_address_type_raises() -> None:
    extra = 'config firewall address\nedit "geo"\nset type geography\nnext\nend'
    with pytest.raises(ValueError, match="type 'geography'"):
        parse_fortigate_text(make_conf(extra=extra))


def test_vdom_config_raises() -> None:
    with pytest.raises(ValueError, match="multi-VDOM"):
        parse_fortigate_text("config vdom\nedit root\nnext\nend")


def test_device_argument_overrides_hostname() -> None:
    assert parse_fortigate_text(make_conf(), device="override").device == "override"
