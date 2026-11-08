"""FortiGate parser: FortiOS CLI config (config / edit / set / next / end) -> ParsedConfig.

Three layers, each testable on its own:
1. tokenize:   text -> statements (lists of tokens, with line numbers)
2. build_tree: statements -> nested Blocks
3. mapper:     Blocks -> vendor-neutral models

Scope: a single-VDOM firewall. Raises ValueError for what it doesn't support (VDOMs,
negated fields, internet-service objects) rather than producing silently wrong rules.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path

from fwlens.models import (
    ANY,
    Action,
    AddressKind,
    AddressObject,
    ParsedConfig,
    Rule,
    ServiceObject,
    Vendor,
)
from fwlens.parsers.resolve import resolve_addresses, resolve_services

# ---------------------------------------------------------------------------
# 1. Tokenizer
# ---------------------------------------------------------------------------

# A quoted string (may contain \" escapes and span lines), a bare word, or a newline.
# Spaces and tabs between tokens are skipped by finditer.
_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([^\s"]+)|(\n)')
_ESCAPE = re.compile(r"\\(.)", re.DOTALL)


@dataclass(frozen=True)
class Statement:
    line: int
    tokens: tuple[str, ...]


def tokenize(text: str) -> Iterator[Statement]:
    """Split config text into statements, one per logical line. Skips # comment lines."""
    tokens: list[str] = []
    line = 1  # current line number
    start = 1  # line the current statement started on
    for match in _TOKEN.finditer(text):
        quoted, word, newline = match.groups()
        if newline:
            if tokens and not tokens[0].startswith("#"):
                yield Statement(start, tuple(tokens))
            tokens = []
            line += 1
            start = line
        elif quoted is not None:
            tokens.append(_ESCAPE.sub(r"\1", quoted))
            line += match.group(0).count("\n")  # multi-line quoted value
        else:
            tokens.append(word)
    if tokens and not tokens[0].startswith("#"):
        yield Statement(start, tuple(tokens))


# ---------------------------------------------------------------------------
# 2. Tree builder
# ---------------------------------------------------------------------------


@dataclass
class Block:
    """A `config ...` section or an `edit ...` entry."""

    settings: dict[str, tuple[str, ...]] = field(default_factory=dict)  # set key v1 v2
    blocks: dict[str, "Block"] = field(default_factory=dict)  # config "firewall policy"
    entries: dict[str, "Block"] = field(default_factory=dict)  # edit "name", in config order

    def value(self, key: str, default: str | None = None) -> str | None:
        """First value of a setting: `set action accept` -> "accept"."""
        values = self.settings.get(key)
        return values[0] if values else default


def build_tree(text: str) -> Block:
    root = Block()
    stack: list[tuple[str, Block]] = [("root", root)]  # (opened by, block)
    for stmt in tokenize(text):
        command, args = stmt.tokens[0], stmt.tokens[1:]
        current = stack[-1][1]
        match command:
            case "config":
                child = current.blocks[" ".join(args)] = Block()
                stack.append(("config", child))
            case "edit":
                child = current.entries[args[0]] = Block()
                stack.append(("edit", child))
            case "set":
                current.settings[args[0]] = args[1:]
            case "unset":
                current.settings.pop(args[0], None)
            case "next" | "end":
                expected = "edit" if command == "next" else "config"
                if stack[-1][0] != expected:
                    raise ValueError(f"line {stmt.line}: '{command}' without matching '{expected}'")
                stack.pop()
            case _:
                raise ValueError(f"line {stmt.line}: unknown statement {command!r}")
    if len(stack) > 1:
        raise ValueError(f"unterminated '{stack[-1][0]}' block at end of file")
    return root


# ---------------------------------------------------------------------------
# 3. Mapper
# ---------------------------------------------------------------------------

_ACTIONS = {
    "accept": Action.ALLOW,
    # FortiOS deny drops silently (no RST), but there is no separate "drop" action.
    "deny": Action.DENY,
}

# FortiOS spells "match everything" differently per field.
_ANY_ALIASES = {"all", "ALL", "any"}

# Policy settings that change what srcaddr/dstaddr/service mean; we don't model them.
_UNSUPPORTED_POLICY_SETTINGS = (
    "srcaddr-negate",
    "dstaddr-negate",
    "service-negate",
    "internet-service",
    "internet-service-src",
)

# Custom services with no port ranges, matched on protocol alone.
_PORTLESS_PROTOCOLS = {"IP", "ICMP", "ICMP6"}


def parse_fortigate_file(path: str | Path, device: str | None = None) -> ParsedConfig:
    return parse_fortigate_text(Path(path).read_text(encoding="utf-8"), device)


def parse_fortigate_text(text: str, device: str | None = None) -> ParsedConfig:
    """Parse a config. `device` overrides the hostname found in the config."""
    root = build_tree(text)
    if "vdom" in root.blocks or "global" in root.blocks:
        raise ValueError("multi-VDOM configs are not supported")

    device = device or _section(root, "system global").value("hostname")
    if not device:
        raise ValueError("no hostname in config; pass device= explicitly")

    addresses = [*_addresses(root, device), *_address_groups(root, device)]
    services = [*_services(root, device), *_service_groups(root, device)]
    policies = _section(root, "firewall policy").entries
    rules = tuple(
        _rule(policy_id, policy, position, device)
        for position, (policy_id, policy) in enumerate(policies.items(), start=1)
    )

    return ParsedConfig(
        vendor=Vendor.FORTIGATE,
        device=device,
        rules=rules,
        addresses=resolve_addresses(addresses),
        services=resolve_services(services),
    )


def _section(root: Block, name: str) -> Block:
    """A top-level `config <name>` block, or an empty one if the config doesn't have it."""
    return root.blocks.get(name, Block())


def _addresses(root: Block, device: str) -> Iterator[AddressObject]:
    for name, entry in _section(root, "firewall address").entries.items():
        match entry.value("type", "ipmask"):
            case "ipmask":
                # "10.0.0.0 255.255.255.0" or "10.0.0.0/24"; no subnet means 0.0.0.0/0.
                # strict=False keeps host bits from failing; FortiOS accepts them too.
                subnet = "/".join(entry.settings.get("subnet", ("0.0.0.0", "0.0.0.0")))
                kind, value = AddressKind.NETMASK, str(ip_network(subnet, strict=False))
            case "iprange":
                kind = AddressKind.RANGE
                value = f"{entry.value('start-ip')}-{entry.value('end-ip')}"
            case "fqdn":
                kind, value = AddressKind.FQDN, entry.value("fqdn")
            case other:
                raise ValueError(f"address {name!r}: type {other!r} is not supported")
        yield AddressObject(
            vendor=Vendor.FORTIGATE, device=device, name=name, kind=kind, value=value
        )


def _address_groups(root: Block, device: str) -> Iterator[AddressObject]:
    for name, entry in _section(root, "firewall addrgrp").entries.items():
        yield AddressObject(
            vendor=Vendor.FORTIGATE,
            device=device,
            name=name,
            kind=AddressKind.GROUP,
            members=entry.settings.get("member", ()),
        )


def _services(root: Block, device: str) -> Iterator[ServiceObject]:
    for name, entry in _section(root, "firewall service custom").entries.items():
        entries = [
            # A range is "dst[:src]", e.g. "80:1024-65535"; we only keep the destination.
            f"{proto}/{port_range.split(':')[0]}"
            for proto in ("tcp", "udp", "sctp")
            for port_range in entry.settings.get(f"{proto}-portrange", ())
        ]
        if not entries:
            protocol = entry.value("protocol")
            if protocol not in _PORTLESS_PROTOCOLS:
                raise ValueError(f"service {name!r}: no port ranges and protocol {protocol!r}")
            entries = [protocol.lower()]
        yield ServiceObject(
            vendor=Vendor.FORTIGATE, device=device, name=name, entries=tuple(entries)
        )


def _service_groups(root: Block, device: str) -> Iterator[ServiceObject]:
    for name, entry in _section(root, "firewall service group").entries.items():
        yield ServiceObject(
            vendor=Vendor.FORTIGATE,
            device=device,
            name=name,
            is_group=True,
            members=entry.settings.get("member", ()),
        )


def _rule(policy_id: str, policy: Block, position: int, device: str) -> Rule:
    name = policy.value("name") or policy_id
    for setting in _UNSUPPORTED_POLICY_SETTINGS:
        if policy.value(setting) == "enable":
            raise ValueError(f"policy {name!r}: '{setting}' is not supported")

    action = policy.value("action", "deny")  # FortiOS default when `set action` is absent
    if action not in _ACTIONS:
        raise ValueError(f"policy {name!r}: unknown action {action!r}")

    return Rule(
        vendor=Vendor.FORTIGATE,
        device=device,
        name=name,
        position=position,
        src_zones=_match(policy, "srcintf"),
        dst_zones=_match(policy, "dstintf"),
        src_addrs=_match(policy, "srcaddr"),
        dst_addrs=_match(policy, "dstaddr"),
        services=_match(policy, "service"),
        applications=(ANY,),  # FortiGate matches apps via security profiles, not the policy
        action=_ACTIONS[action],
        enabled=policy.value("status", "enable") != "disable",
        # Default "utm" logs only sessions that hit a security profile; we treat only
        # "disable" as logging off.
        log=policy.value("logtraffic", "utm") != "disable",
    )


def _match(policy: Block, key: str) -> tuple[str, ...]:
    """Policy match values with FortiOS's any-spellings normalized to ANY."""
    values = policy.settings.get(key, ())
    return tuple(ANY if v in _ANY_ALIASES else v for v in values)
