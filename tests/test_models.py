from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from fwlens.models import ANY, Action, LogEvent, Rule, Vendor


def make_rule(**overrides) -> Rule:
    fields = {
        "vendor": "panos",
        "device": "lab-fw01",
        "name": "allow-web",
        "position": 1,
        "src_zones": ("trust",),
        "dst_zones": ("untrust",),
        "src_addrs": ("net-users",),
        "dst_addrs": (ANY,),
        "services": ("service-https",),
        "applications": ("ssl",),
        "action": "allow",
    }
    fields.update(overrides)
    return Rule(**fields)


def test_rule_parses_enums_and_defaults() -> None:
    rule = make_rule()
    assert rule.vendor is Vendor.PANOS
    assert rule.action is Action.ALLOW
    assert rule.enabled is True
    assert rule.log is True
    assert rule.hit_count is None


def test_rule_id_is_vendor_device_name() -> None:
    assert make_rule().id == "panos:lab-fw01:allow-web"


def test_rule_id_is_in_serialized_output() -> None:
    assert make_rule().model_dump()["id"] == "panos:lab-fw01:allow-web"


def test_rule_is_frozen() -> None:
    rule = make_rule()
    with pytest.raises(ValidationError):
        rule.action = Action.DENY


def test_empty_match_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_rule(src_addrs=())


def test_any_mixed_with_other_values_is_rejected() -> None:
    with pytest.raises(ValidationError, match="cannot be combined"):
        make_rule(dst_addrs=(ANY, "10.0.0.0/8"))


@pytest.mark.parametrize("position", [0, -1])
def test_position_is_one_based(position: int) -> None:
    with pytest.raises(ValidationError):
        make_rule(position=position)


def test_unknown_action_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_rule(action="reset-both")  # parsers must map vendor actions first


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_rule(comment="typo'd field names should fail loudly")


# --- LogEvent ----------------------------------------------------------------


def make_event(**overrides) -> LogEvent:
    fields = {
        "vendor": "fortigate",
        "device": "lab-fgt01",
        "timestamp": datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        "src_ip": "10.20.10.5",
        "dst_ip": "192.0.2.10",
        "dst_port": 443,
        "protocol": "tcp",
        "rule_name": "allow-web-out",
        "action": "allow",
        "bytes": 1500,
    }
    fields.update(overrides)
    return LogEvent(**fields)


def test_event_parses_ips_and_rule_id() -> None:
    event = make_event()
    assert event.src_ip == IPv4Address("10.20.10.5")
    assert event.rule_id == "fortigate:lab-fgt01:allow-web-out"


def test_event_timestamp_is_normalized_to_utc() -> None:
    plus_one = timezone(timedelta(hours=1))
    event = make_event(timestamp=datetime(2026, 11, 1, 13, 0, tzinfo=plus_one))
    assert event.timestamp == datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    assert event.timestamp.tzinfo is UTC


def test_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        make_event(timestamp=datetime(2026, 11, 1, 12, 0))


@pytest.mark.parametrize(
    "overrides",
    [{"src_ip": "10.20.10.999"}, {"dst_port": 70000}, {"bytes": -1}],
)
def test_event_rejects_bad_values(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        make_event(**overrides)


def test_icmp_event_has_no_port() -> None:
    assert make_event(protocol="icmp", dst_port=None).dst_port is None
