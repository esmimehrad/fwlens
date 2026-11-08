"""Vendor-neutral data model.

Every parser normalizes its vendor's config into these models; everything downstream
(SQL checks, agent tools, API) only sees this schema.

Conventions:
- "any" is always explicit: a match-everything field is ("any",), never empty.
  Vendor spellings (FortiGate "all"/"ALL", PAN-OS "any") are normalized to ANY.
- Rules keep object *names* as written on the device; AddressObject / ServiceObject
  carry the resolved values that those names expand to.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    computed_field,
    field_validator,
)

ANY = "any"

# A match field: at least one entry, and "any" only on its own.
MatchField = Annotated[tuple[str, ...], Field(min_length=1)]


class Vendor(StrEnum):
    PANOS = "panos"
    FORTIGATE = "fortigate"


class Action(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"


class AddressKind(StrEnum):
    NETMASK = "ip-netmask"  # 10.0.0.0/24 or a single host 10.0.0.5/32
    RANGE = "ip-range"  # 10.0.0.10-10.0.0.20
    FQDN = "fqdn"
    GROUP = "group"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AddressObject(_Frozen):
    vendor: Vendor
    device: str
    name: str
    kind: AddressKind
    value: str | None = None  # literal value; None for groups
    members: tuple[str, ...] = ()  # direct member names, groups only
    resolved: tuple[str, ...] = ()  # flattened leaf values after group resolution
    unresolved: tuple[str, ...] = ()  # member names that could not be found


class ServiceObject(_Frozen):
    vendor: Vendor
    device: str
    name: str
    is_group: bool = False
    # Leaf services: "tcp/443", "udp/53", "tcp/8000-8080", or a bare protocol like "icmp".
    # One object can mix protocols (a FortiGate DNS service is both tcp/53 and udp/53).
    entries: tuple[str, ...] = ()
    members: tuple[str, ...] = ()  # direct member names, groups only
    resolved: tuple[str, ...] = ()  # flattened entries after group resolution
    unresolved: tuple[str, ...] = ()


class Rule(_Frozen):
    vendor: Vendor
    device: str
    name: str
    position: int = Field(ge=1)  # 1-based order in the rulebase
    vendor_id: str | None = None  # FortiGate policy ID / PAN-OS rule uuid, if the config has one
    src_zones: MatchField
    dst_zones: MatchField
    src_addrs: MatchField
    dst_addrs: MatchField
    services: MatchField
    applications: MatchField
    action: Action
    enabled: bool = True
    log: bool = True
    hit_count: int | None = Field(default=None, ge=0)  # None until logs are loaded

    @computed_field
    @property
    def id(self) -> str:
        return f"{self.vendor}:{self.device}:{self.name}"

    @field_validator("src_zones", "dst_zones", "src_addrs", "dst_addrs", "services", "applications")
    @classmethod
    def _any_stands_alone(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        # A real device rejects ["any", "10.0.0.0/8"]; if we see it, a parser is broken.
        if ANY in v and len(v) > 1:
            raise ValueError(f"'{ANY}' cannot be combined with other values: {v}")
        return v


class LogEvent(_Frozen):
    """One traffic session from a firewall log."""

    vendor: Vendor
    device: str
    timestamp: AwareDatetime  # stored in UTC; naive datetimes are rejected
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    dst_port: int | None = Field(default=None, ge=0, le=65535)  # None for ICMP
    protocol: str  # tcp / udp / icmp, or the IP protocol number if unknown
    rule_name: str  # same naming as Rule.name, so logs join to rules on (vendor, device, name)
    action: Action
    bytes: int = Field(ge=0)  # sent + received

    @computed_field
    @property
    def rule_id(self) -> str:
        return f"{self.vendor}:{self.device}:{self.rule_name}"

    @field_validator("timestamp")
    @classmethod
    def _to_utc(cls, v: datetime) -> datetime:
        return v.astimezone(UTC)


class ParsedConfig(_Frozen):
    """Everything one parser run produces for one device."""

    vendor: Vendor
    device: str
    rules: tuple[Rule, ...] = ()
    addresses: tuple[AddressObject, ...] = ()
    services: tuple[ServiceObject, ...] = ()
