import pytest
from pydantic import ValidationError

from fwlens.models import ANY, Action, Rule, Vendor


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
