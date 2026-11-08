"""PAN-OS parser: firewall running-config XML -> ParsedConfig.

Scope: a standalone firewall with one vsys, plus objects under <shared>.
Raises ValueError for what it doesn't support (multiple vsys, negated source/destination,
dynamic address groups) rather than producing silently wrong rules.
Panorama device-groups and pre/post rulebases are out of scope.
"""

from collections.abc import Iterator
from pathlib import Path

from lxml import etree

from fwlens.models import (
    Action,
    AddressKind,
    AddressObject,
    ParsedConfig,
    Rule,
    ServiceObject,
    Vendor,
)
from fwlens.parsers.resolve import resolve_addresses, resolve_services

# Hardened parser: no entity expansion and no network fetches (blocks XXE).
_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, remove_comments=True)

_ACTIONS = {
    "allow": Action.ALLOW,
    "deny": Action.DENY,
    "drop": Action.DROP,
    # reset-* also send a TCP RST; the traffic is still blocked, so they count as deny.
    "reset-client": Action.DENY,
    "reset-server": Action.DENY,
    "reset-both": Action.DENY,
}

# Address types, in the XML tag spelling PAN-OS uses.
_LEAF_ADDRESS_KINDS = (AddressKind.NETMASK, AddressKind.RANGE, AddressKind.FQDN)

# Predefined on every PAN-OS device, so they never appear in the config itself.
_PREDEFINED_SERVICES = {
    "service-http": ("tcp/80", "tcp/8080"),
    "service-https": ("tcp/443",),
}


def parse_panos_file(path: str | Path, device: str | None = None) -> ParsedConfig:
    return parse_panos_xml(Path(path).read_bytes(), device)


def parse_panos_xml(xml: str | bytes, device: str | None = None) -> ParsedConfig:
    """Parse a config. `device` overrides the hostname found in the config."""
    if isinstance(xml, str):
        xml = xml.encode()  # lxml rejects str input that carries an encoding declaration
    root = etree.fromstring(xml, _XML_PARSER)

    vsys_entries = root.findall("devices/entry/vsys/entry")
    if len(vsys_entries) != 1:
        raise ValueError(f"expected exactly one vsys, found {len(vsys_entries)}")
    vsys = vsys_entries[0]

    device = device or _text(root.find("devices/entry/deviceconfig/system/hostname"))
    if not device:
        raise ValueError("no hostname in config; pass device= explicitly")

    # Later scopes win: a vsys object overrides a shared object with the same name.
    scopes = [scope for scope in (root.find("shared"), vsys) if scope is not None]
    addresses = {a.name: a for scope in scopes for a in _addresses(scope, device)}
    services = {
        name: ServiceObject(vendor=Vendor.PANOS, device=device, name=name, entries=entries)
        for name, entries in _PREDEFINED_SERVICES.items()
    }
    services.update({s.name: s for scope in scopes for s in _services(scope, device)})

    rule_entries = vsys.findall("rulebase/security/rules/entry")
    rules = tuple(
        _rule(entry, position, device) for position, entry in enumerate(rule_entries, start=1)
    )

    return ParsedConfig(
        vendor=Vendor.PANOS,
        device=device,
        rules=rules,
        addresses=resolve_addresses(addresses.values()),
        services=resolve_services(services.values()),
    )


def _addresses(scope: etree._Element, device: str) -> Iterator[AddressObject]:
    for entry in scope.findall("address/entry"):
        name = entry.get("name")
        for kind in _LEAF_ADDRESS_KINDS:
            value = _text(entry.find(kind.value))
            if value:
                yield AddressObject(
                    vendor=Vendor.PANOS, device=device, name=name, kind=kind, value=value
                )
                break
        else:
            raise ValueError(f"address {name!r}: unsupported or missing type")

    for entry in scope.findall("address-group/entry"):
        name = entry.get("name")
        if entry.find("dynamic") is not None:
            raise ValueError(f"address-group {name!r}: dynamic groups are not supported")
        yield AddressObject(
            vendor=Vendor.PANOS,
            device=device,
            name=name,
            kind=AddressKind.GROUP,
            members=_members(entry, "static"),
        )


def _services(scope: etree._Element, device: str) -> Iterator[ServiceObject]:
    for entry in scope.findall("service/entry"):
        name = entry.get("name")
        for proto in ("tcp", "udp", "sctp"):
            port = _text(entry.find(f"protocol/{proto}/port"))
            if port:
                # PAN-OS allows "80,8080" and "8000-8080" in one <port> element.
                entries = tuple(f"{proto}/{p.strip()}" for p in port.split(","))
                yield ServiceObject(vendor=Vendor.PANOS, device=device, name=name, entries=entries)
                break
        else:
            raise ValueError(f"service {name!r}: no tcp/udp/sctp port found")

    for entry in scope.findall("service-group/entry"):
        yield ServiceObject(
            vendor=Vendor.PANOS,
            device=device,
            name=entry.get("name"),
            is_group=True,
            members=_members(entry, "members"),
        )


def _rule(entry: etree._Element, position: int, device: str) -> Rule:
    name = entry.get("name")
    for tag in ("negate-source", "negate-destination"):
        if _yes(entry, tag, default=False):
            raise ValueError(f"rule {name!r}: <{tag}> is not supported")

    action = _text(entry.find("action"))
    if action not in _ACTIONS:
        raise ValueError(f"rule {name!r}: unknown action {action!r}")

    return Rule(
        vendor=Vendor.PANOS,
        device=device,
        name=name,
        position=position,
        vendor_id=entry.get("uuid"),  # PAN-OS 9.0+ gives every rule a uuid attribute
        src_zones=_members(entry, "from"),
        dst_zones=_members(entry, "to"),
        src_addrs=_members(entry, "source"),
        dst_addrs=_members(entry, "destination"),
        services=_members(entry, "service"),
        applications=_members(entry, "application"),
        action=_ACTIONS[action],
        enabled=not _yes(entry, "disabled", default=False),
        log=_yes(entry, "log-end", default=True),  # PAN-OS logs at session end by default
    )


def _text(element: etree._Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    return element.text.strip() or None


def _members(entry: etree._Element, tag: str) -> tuple[str, ...]:
    """<tag><member>a</member><member>b</member></tag> -> ("a", "b")"""
    return tuple(text for m in entry.findall(f"{tag}/member") if (text := _text(m)))


def _yes(entry: etree._Element, tag: str, default: bool) -> bool:
    value = _text(entry.find(tag))
    return default if value is None else value == "yes"
