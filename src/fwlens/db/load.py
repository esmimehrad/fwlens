"""Load parsed configs and traffic logs into Postgres.

Every function takes an open Connection and runs inside the caller's transaction, so a
failed load leaves the database as it was (`with engine.begin() as conn: ...`).
"""

import hashlib
from itertools import batched
from pathlib import Path

from sqlalchemy import Connection, delete, insert, select, update

from fwlens.db.schema import (
    address_objects,
    devices,
    log_events,
    log_files,
    rules,
    service_objects,
)
from fwlens.models import LogEvent, ParsedConfig
from fwlens.parsers.syslog import parse_log_file

# Rows per INSERT. executemany is plenty at sample scale; COPY is the upgrade path
# for millions of log lines.
BATCH_SIZE = 1000


def load_config(conn: Connection, config: ParsedConfig) -> None:
    """Replace everything stored for this device with `config`.

    Deleting the device cascades to its rules and objects, so a reload never leaves
    rules behind that were removed from the config.
    """
    conn.execute(
        delete(devices).where(devices.c.vendor == config.vendor, devices.c.device == config.device)
    )
    conn.execute(insert(devices).values(vendor=config.vendor.value, device=config.device))
    # mode="json": enums -> str, tuples -> lists (what psycopg sends as Postgres arrays).
    # Rule's computed `id` is included, matching the rules.id column.
    for table, items in (
        (rules, config.rules),
        (address_objects, config.addresses),
        (service_objects, config.services),
    ):
        rows = [item.model_dump(mode="json") for item in items]
        for batch in batched(rows, BATCH_SIZE):
            conn.execute(insert(table), list(batch))


def load_log_file(conn: Connection, path: str | Path) -> int | None:
    """Load a traffic log file. Returns the event count, or None if this exact file
    (by sha256) was already loaded."""
    path = Path(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    already = conn.execute(select(log_files.c.sha256).where(log_files.c.sha256 == digest))
    if already.first() is not None:
        return None

    conn.execute(insert(log_files).values(sha256=digest, path=str(path), events=0))
    count = 0
    for batch in batched(parse_log_file(path), BATCH_SIZE):
        conn.execute(insert(log_events), [_event_row(event, digest) for event in batch])
        count += len(batch)
    conn.execute(update(log_files).where(log_files.c.sha256 == digest).values(events=count))
    return count


def _event_row(event: LogEvent, log_file: str) -> dict:
    return {
        "log_file": log_file,
        "vendor": event.vendor.value,
        "device": event.device,
        "ts": event.timestamp,
        "src_ip": str(event.src_ip),
        "dst_ip": str(event.dst_ip),
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "rule_name": event.rule_name,
        "action": event.action.value,
        "bytes": event.bytes,
    }
