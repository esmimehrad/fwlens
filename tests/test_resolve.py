import pytest

from fwlens.models import AddressKind, AddressObject, ServiceObject
from fwlens.parsers.resolve import resolve_addresses, resolve_services


def host(name: str, value: str) -> AddressObject:
    return AddressObject(
        vendor="panos", device="t", name=name, kind=AddressKind.NETMASK, value=value
    )


def group(name: str, *members: str) -> AddressObject:
    return AddressObject(
        vendor="panos", device="t", name=name, kind=AddressKind.GROUP, members=members
    )


def by_name(objects):
    return {o.name: o for o in objects}


def test_leaf_resolves_to_its_own_value() -> None:
    result = by_name(resolve_addresses([host("h1", "10.0.0.1/32")]))
    assert result["h1"].resolved == ("10.0.0.1/32",)
    assert result["h1"].unresolved == ()


def test_nested_groups_flatten_in_order_without_duplicates() -> None:
    objects = [
        host("h1", "10.0.0.1/32"),
        host("h2", "10.0.0.2/32"),
        group("inner", "h2", "h1"),
        group("outer", "h1", "inner"),  # h1 reachable twice
    ]
    result = by_name(resolve_addresses(objects))
    assert result["outer"].resolved == ("10.0.0.1/32", "10.0.0.2/32")


def test_missing_member_is_recorded_not_raised() -> None:
    result = by_name(resolve_addresses([host("h1", "10.0.0.1/32"), group("g", "h1", "ghost")]))
    assert result["g"].resolved == ("10.0.0.1/32",)
    assert result["g"].unresolved == ("ghost",)


def test_group_cycle_raises() -> None:
    with pytest.raises(ValueError, match="group cycle: a -> b -> a"):
        resolve_addresses([group("a", "b"), group("b", "a")])


def test_services_resolve_to_protocol_slash_port() -> None:
    objects = [
        ServiceObject(vendor="panos", device="t", name="web", protocol="tcp", ports=("80", "443")),
        ServiceObject(vendor="panos", device="t", name="dns", protocol="udp", ports=("53",)),
        ServiceObject(vendor="panos", device="t", name="grp", members=("web", "dns")),
    ]
    result = by_name(resolve_services(objects))
    assert result["grp"].resolved == ("tcp/80", "tcp/443", "udp/53")
