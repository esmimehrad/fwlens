"""Syslog parser tests use hand-written lines (laid out per the vendor docs), not the
sample generator, so they check the parser independently of our own writer."""

import logging
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address

import pytest

from fwlens.models import Action, Vendor
from fwlens.parsers.syslog import parse_line, parse_lines

# PAN-OS TRAFFIC "end" log: src 10.10.10.5 -> 192.0.2.10:443/tcp, rule allow-web-out, 5400 bytes
PANOS_END = (
    "<14>Nov  1 12:00:00 lab-fw01 1,2026/11/01 12:00:00,012801000001,TRAFFIC,end,2561,"
    "2026/11/01 12:00:00,10.10.10.5,192.0.2.10,203.0.113.1,192.0.2.10,allow-web-out,,,ssl,"
    "vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,,12345,1,51000,443,40000,443,"
    "0x400000,tcp,allow,5400,1200,4200,12,2026/11/01 11:59:58,2,any,,7000000001,0x0"
)

FORTI_ACCEPT = (
    '<189>date=2026-11-01 time=12:00:00 devname="lab-fgt01" devid="FGT60FTK00000001" '
    'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
    'srcip=10.20.10.5 srcport=51000 srcintf="internal" dstip=192.0.2.10 dstport=443 '
    'dstintf="wan1" proto=6 action="close" policyid=2 policyname="allow-web-out" '
    'service="HTTPS" sentbyte=1200 rcvdbyte=4200'
)


# --- PAN-OS -------------------------------------------------------------------


def test_panos_traffic_end() -> None:
    event = parse_line(PANOS_END)
    assert event.vendor is Vendor.PANOS
    assert event.device == "lab-fw01"
    assert event.timestamp == datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    assert event.src_ip == IPv4Address("10.10.10.5")
    assert event.dst_ip == IPv4Address("192.0.2.10")  # original dst, not the NAT address
    assert (event.dst_port, event.protocol) == (443, "tcp")
    assert event.rule_name == "allow-web-out"
    assert event.action is Action.ALLOW
    assert event.bytes == 5400


def test_panos_start_log_is_skipped() -> None:
    assert parse_line(PANOS_END.replace(",TRAFFIC,end,", ",TRAFFIC,start,")) is None


def test_panos_non_traffic_log_is_skipped() -> None:
    assert parse_line(PANOS_END.replace(",TRAFFIC,", ",SYSTEM,")) is None


def test_panos_short_system_log_is_skipped_not_rejected() -> None:
    # Real SYSTEM logs have far fewer fields than TRAFFIC logs.
    line = (
        "<14>Nov  1 12:00:00 lab-fw01 1,2026/11/01 12:00:00,012801000001,SYSTEM,general,0,"
        "2026/11/01 12:00:00,,general,,0,0,general,informational,User admin logged in"
    )
    assert parse_line(line) is None


def test_panos_truncated_traffic_log_raises() -> None:
    with pytest.raises(ValueError, match="fields"):
        parse_line(PANOS_END[:200])


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("deny", Action.DENY), ("drop", Action.DROP), ("reset-both", Action.DENY)],
)
def test_panos_actions(raw: str, expected: Action) -> None:
    assert parse_line(PANOS_END.replace(",tcp,allow,", f",tcp,{raw},")).action is expected


def test_panos_quoted_rule_name_with_comma() -> None:
    line = PANOS_END.replace(",allow-web-out,", ',"web, outbound",')
    assert parse_line(line).rule_name == "web, outbound"


def test_panos_icmp_has_no_port() -> None:
    event = parse_line(PANOS_END.replace(",tcp,allow,", ",icmp,allow,"))
    assert (event.protocol, event.dst_port) == ("icmp", None)


def test_panos_without_header_raises() -> None:
    with pytest.raises(ValueError, match="no syslog header"):
        parse_line(PANOS_END.split("lab-fw01 ", 1)[1])


# --- FortiGate ----------------------------------------------------------------


def test_fortigate_forward_close() -> None:
    event = parse_line(FORTI_ACCEPT)
    assert event.vendor is Vendor.FORTIGATE
    assert event.device == "lab-fgt01"
    assert event.timestamp == datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    assert (event.dst_port, event.protocol) == (443, "tcp")
    assert event.rule_name == "allow-web-out"
    assert event.action is Action.ALLOW  # "close" = allowed session that ended normally
    assert event.bytes == 5400


def test_fortigate_without_policyname_uses_policyid() -> None:
    line = FORTI_ACCEPT.replace('policyid=2 policyname="allow-web-out" ', "policyid=11 ")
    assert parse_line(line).rule_name == "11"


def test_fortigate_policy_zero_is_implicit_deny() -> None:
    line = FORTI_ACCEPT.replace('action="close" policyid=2 policyname="allow-web-out"', "")
    line += ' action="deny" policyid=0'
    event = parse_line(line)
    assert (event.rule_name, event.action) == ("implicit-deny", Action.DENY)


def test_fortigate_icmp_has_no_port() -> None:
    line = FORTI_ACCEPT.replace("dstport=443 ", "").replace("proto=6", "proto=1")
    event = parse_line(line)
    assert (event.protocol, event.dst_port) == ("icmp", None)


@pytest.mark.parametrize("subtype", ["local", "multicast"])
def test_fortigate_non_forward_traffic_is_skipped(subtype: str) -> None:
    assert parse_line(FORTI_ACCEPT.replace('"forward"', f'"{subtype}"')) is None


def test_fortigate_event_log_is_skipped() -> None:
    assert parse_line(FORTI_ACCEPT.replace('type="traffic"', 'type="event"')) is None


def test_device_timezone_is_applied() -> None:
    plus_two = timezone(timedelta(hours=2))
    event = parse_line(FORTI_ACCEPT, tz=plus_two)
    assert event.timestamp == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)


# --- parse_lines (lenient) ----------------------------------------------------


def test_parse_lines_skips_bad_lines_and_logs_them(caplog) -> None:
    lines = [
        PANOS_END,
        "",
        "garbage line",
        FORTI_ACCEPT.replace("srcip=10.20.10.5", "srcip=999.1.1.1"),
        PANOS_END.replace(",TRAFFIC,", ",SYSTEM,"),
        FORTI_ACCEPT,
    ]
    with caplog.at_level(logging.WARNING):
        events = list(parse_lines(lines))

    assert [e.vendor for e in events] == [Vendor.PANOS, Vendor.FORTIGATE]
    skipped = [r.getMessage() for r in caplog.records]
    assert len(skipped) == 2
    assert skipped[0].startswith("line 3 skipped")
    assert skipped[1].startswith("line 4 skipped")
