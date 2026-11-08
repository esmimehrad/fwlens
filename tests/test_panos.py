from pathlib import Path

import pytest
from pydantic import ValidationError

from fwlens.models import ANY, Action, Vendor
from fwlens.parsers.panos import parse_panos_file, parse_panos_xml

SAMPLE = Path(__file__).parents[1] / "data" / "samples" / "panos" / "lab-fw01.xml"


@pytest.fixture(scope="module")
def config():
    return parse_panos_file(SAMPLE)


@pytest.fixture(scope="module")
def rules(config):
    return {r.name: r for r in config.rules}


# --- sample config ---------------------------------------------------------


def test_device_and_vendor(config) -> None:
    assert config.vendor is Vendor.PANOS
    assert config.device == "lab-fw01"


def test_rules_keep_rulebase_order(config) -> None:
    assert [r.name for r in config.rules] == [
        "allow-dns",
        "allow-web-out",
        "allow-web-in",
        "allow-ssh-admins",
        "allow-ssh-jump",
        "allow-ntp",
        "allow-web-out-copy",
        "old-ftp-access",
        "temp-vendor-access",
        "drop-blocklist",
        "deny-all",
    ]
    assert [r.position for r in config.rules] == list(range(1, 12))


def test_rule_fields_are_mapped(rules) -> None:
    rule = rules["allow-web-in"]
    assert rule.id == "panos:lab-fw01:allow-web-in"
    assert rule.src_zones == ("untrust",)
    assert rule.dst_zones == ("dmz",)
    assert rule.src_addrs == (ANY,)
    assert rule.dst_addrs == ("grp-web",)  # names as written, not resolved
    assert rule.services == ("sg-web",)
    assert rule.applications == ("web-browsing", "ssl")
    assert rule.action is Action.ALLOW
    assert rule.enabled is True
    assert rule.log is True
    assert rule.hit_count is None


def test_seeded_flaws_are_visible(rules) -> None:
    assert rules["allow-ntp"].log is False
    assert rules["old-ftp-access"].enabled is False
    any_any = rules["temp-vendor-access"]
    assert (any_any.src_addrs, any_any.dst_addrs, any_any.services) == ((ANY,), (ANY,), (ANY,))
    assert rules["drop-blocklist"].action is Action.DROP


def test_address_groups_resolve(config) -> None:
    addresses = {a.name: a for a in config.addresses}
    assert addresses["grp-web"].resolved == ("10.10.20.11/32", "10.10.20.12/32")
    # mixes a vsys range, a shared FQDN, and a member that no longer exists
    blocklist = addresses["grp-blocklist"]
    assert blocklist.resolved == ("203.0.113.10-203.0.113.20", "bad.example.net")
    assert blocklist.unresolved == ("h-decom",)


def test_service_group_uses_predefined_services(config) -> None:
    services = {s.name: s for s in config.services}
    assert services["sg-web"].resolved == ("tcp/443", "tcp/8443")


# --- edge cases (inline XML) -----------------------------------------------


def make_xml(rule_body: str = "", hostname: str = "<hostname>t-fw</hostname>") -> str:
    return f"""<config>
      <devices><entry name="localhost.localdomain">
        <deviceconfig><system>{hostname}</system></deviceconfig>
        <vsys><entry name="vsys1">
          <rulebase><security><rules>
            <entry name="r1">
              <from><member>a</member></from><to><member>b</member></to>
              <source><member>any</member></source><destination><member>any</member></destination>
              <application><member>any</member></application><service><member>any</member></service>
              {rule_body}
            </entry>
          </rules></security></rulebase>
        </entry></vsys>
      </entry></devices>
    </config>"""


@pytest.mark.parametrize("action", ["reset-client", "reset-server", "reset-both"])
def test_reset_actions_map_to_deny(action: str) -> None:
    config = parse_panos_xml(make_xml(f"<action>{action}</action>"))
    assert config.rules[0].action is Action.DENY


def test_unknown_action_raises() -> None:
    with pytest.raises(ValueError, match="unknown action 'permit'"):
        parse_panos_xml(make_xml("<action>permit</action>"))


def test_negate_source_raises() -> None:
    with pytest.raises(ValueError, match="negate-source"):
        parse_panos_xml(make_xml("<action>allow</action><negate-source>yes</negate-source>"))


def test_device_argument_overrides_hostname() -> None:
    config = parse_panos_xml(make_xml("<action>allow</action>"), device="override")
    assert config.device == "override"


def test_missing_hostname_raises() -> None:
    with pytest.raises(ValueError, match="no hostname"):
        parse_panos_xml(make_xml("<action>allow</action>", hostname=""))


def test_rule_missing_a_match_field_fails_validation() -> None:
    xml = make_xml("<action>allow</action>").replace("<to><member>b</member></to>", "")
    with pytest.raises(ValidationError):
        parse_panos_xml(xml)


def test_external_entities_are_not_expanded(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("LEAKED")
    xml = make_xml("<action>allow</action>", hostname="<hostname>&xxe;</hostname>")
    xml = f'<!DOCTYPE config [<!ENTITY xxe SYSTEM "{secret.as_uri()}">]>\n{xml}'
    # The entity stays unexpanded, so the hostname is empty instead of the file's contents.
    with pytest.raises(ValueError, match="no hostname"):
        parse_panos_xml(xml)


def test_multiple_vsys_raises() -> None:
    xml = make_xml("<action>allow</action>").replace(
        "</entry></vsys>", '</entry><entry name="vsys2"/></vsys>'
    )
    with pytest.raises(ValueError, match="exactly one vsys"):
        parse_panos_xml(xml)
