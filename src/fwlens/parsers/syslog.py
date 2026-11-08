"""Firewall traffic logs (syslog lines) -> LogEvent.

Two formats, detected per line:
- PAN-OS:    "<PRI>Mmm dd hh:mm:ss host " + a CSV TRAFFIC log at fixed field positions
- FortiGate: optional "<PRI>" + key=value pairs (date=... devname=... srcip=...)

Unlike the config parsers, this one is lenient: one corrupt line shouldn't throw away a
day of logs, so parse_lines() skips it with a warning. Lines that are valid but not
traffic (system/event logs, PAN-OS "start" logs) are skipped silently.
"""

import csv
import logging
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, tzinfo
from pathlib import Path

from fwlens.models import Action, LogEvent, Vendor

log = logging.getLogger(__name__)

_PRI = re.compile(r"^<\d{1,3}>")
# RFC 3164 header, e.g. "Nov  1 12:00:00 lab-fw01 "
_BSD_HEADER = re.compile(r"^[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} (?P<host>\S+) ")
_KEY_VALUE = re.compile(r'([\w-]+)=("(?:[^"\\]|\\.)*"|\S*)')

# ---------------------------------------------------------------------------
# PAN-OS
# ---------------------------------------------------------------------------

# 0-based positions in the PAN-OS TRAFFIC log CSV, from the PAN-OS syslog field docs.
# The sample generator writes lines with this same table.
PANOS_FIELDS = {
    "type": 3,  # TRAFFIC / THREAT / SYSTEM ...
    "subtype": 4,  # start / end / drop / deny
    "generated_time": 6,
    "src_ip": 7,
    "dst_ip": 8,
    "rule": 11,
    "dst_port": 25,
    "protocol": 29,
    "action": 30,
    "bytes": 31,  # sent + received
}
PANOS_MIN_FIELDS = max(PANOS_FIELDS.values()) + 1
PANOS_TIME_FORMAT = "%Y/%m/%d %H:%M:%S"


def _panos_action(value: str) -> Action:
    if value == "allow":
        return Action.ALLOW
    if value.startswith("drop"):  # drop, drop-icmp, drop-all-packets
        return Action.DROP
    if value == "deny" or value.startswith("reset-"):
        return Action.DENY
    raise ValueError(f"unknown PAN-OS action {value!r}")


def _parse_panos(payload: str, host: str, tz: tzinfo) -> LogEvent | None:
    fields = next(csv.reader([payload]))  # csv handles quoted rule names with commas
    # Check the type first: other log types (SYSTEM, CONFIG...) have fewer fields.
    log_type = fields[PANOS_FIELDS["type"]] if len(fields) > PANOS_FIELDS["type"] else None
    if log_type != "TRAFFIC":
        if log_type is None or not log_type.isupper():
            raise ValueError(f"not a PAN-OS log: {payload[:40]!r}")
        return None
    if len(fields) < PANOS_MIN_FIELDS:
        raise ValueError(f"PAN-OS log has {len(fields)} fields, need {PANOS_MIN_FIELDS}")

    def get(name: str) -> str:
        return fields[PANOS_FIELDS[name]]

    if get("subtype") == "start":
        return None  # the same session logs again at "end"; count it once

    protocol = get("protocol")
    return LogEvent(
        vendor=Vendor.PANOS,
        device=host,
        timestamp=datetime.strptime(get("generated_time"), PANOS_TIME_FORMAT).replace(tzinfo=tz),
        src_ip=get("src_ip"),
        dst_ip=get("dst_ip"),
        dst_port=None if protocol == "icmp" else int(get("dst_port")),
        protocol=protocol,
        rule_name=get("rule"),
        action=_panos_action(get("action")),
        bytes=int(get("bytes")),
    )


# ---------------------------------------------------------------------------
# FortiGate
# ---------------------------------------------------------------------------

_FORTI_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp"}
# Every action except deny means the session was allowed; the rest say how it ended.
_FORTI_ALLOWED = {"accept", "close", "timeout", "client-rst", "server-rst"}
FORTI_IMPLICIT_DENY = "implicit-deny"  # policyid=0 is FortiOS's implicit deny


def _parse_fortigate(payload: str, tz: tzinfo) -> LogEvent | None:
    kv = {key: value.strip('"') for key, value in _KEY_VALUE.findall(payload)}
    if kv.get("type") != "traffic" or kv.get("subtype") != "forward":
        return None  # event/utm logs, and "local" traffic to the firewall itself

    action = kv["action"]
    if action == "deny":
        mapped = Action.DENY
    elif action in _FORTI_ALLOWED:
        mapped = Action.ALLOW
    else:
        raise ValueError(f"unknown FortiGate action {action!r}")

    policy_id = kv["policyid"]
    rule_name = kv.get("policyname") or (FORTI_IMPLICIT_DENY if policy_id == "0" else policy_id)

    protocol = _FORTI_PROTOCOLS.get(kv["proto"], kv["proto"])
    return LogEvent(
        vendor=Vendor.FORTIGATE,
        device=kv["devname"],
        timestamp=datetime.fromisoformat(f"{kv['date']}T{kv['time']}").replace(tzinfo=tz),
        src_ip=kv["srcip"],
        dst_ip=kv["dstip"],
        dst_port=int(kv["dstport"]) if "dstport" in kv else None,  # absent for ICMP
        protocol=protocol,
        rule_name=rule_name,
        action=mapped,
        bytes=int(kv.get("sentbyte", 0)) + int(kv.get("rcvdbyte", 0)),
    )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def parse_line(line: str, tz: tzinfo = UTC) -> LogEvent | None:
    """One log line -> LogEvent, or None if it isn't a traffic session.

    Raises ValueError (or KeyError for a missing FortiGate key) if the line is malformed.
    `tz` is the device's local timezone; both vendors log local time without an offset.
    """
    payload = _PRI.sub("", line.strip(), count=1)
    header = _BSD_HEADER.match(payload)
    if header:
        payload = payload[header.end() :]

    if re.match(r"[\w-]+=", payload):
        return _parse_fortigate(payload, tz)
    if header is None:
        raise ValueError("PAN-OS log line has no syslog header with a hostname")
    return _parse_panos(payload, header["host"], tz)


def parse_lines(lines: Iterable[str], tz: tzinfo = UTC) -> Iterator[LogEvent]:
    """Lenient: skip blank, non-traffic, and malformed lines (malformed ones are logged)."""
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = parse_line(line, tz)
        except (ValueError, KeyError) as exc:
            log.warning("line %d skipped: %s", number, exc)
            continue
        if event is not None:
            yield event


def parse_log_file(path: str | Path, tz: tzinfo = UTC) -> Iterator[LogEvent]:
    with Path(path).open(encoding="utf-8") as f:
        yield from parse_lines(f, tz)
