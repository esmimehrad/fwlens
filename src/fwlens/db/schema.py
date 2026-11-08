"""Postgres schema (SQLAlchemy Core). Mirrors fwlens.models; migrations create it.

Design notes:
- Match fields are text[] arrays: the any-any check is `'any' = ANY(src_addrs)`, and
  checks that need rows can unnest() them.
- Enumerations are text + CHECK rather than Postgres ENUM types, which are awkward
  to change in later migrations.
- Config tables hang off `devices` with ON DELETE CASCADE, so reloading a device is
  "delete the device, insert again" in one transaction.
- log_events has no foreign key to rules: logs legitimately name rules that aren't in
  the loaded config (implicit-deny, interzone-default, logs loaded before the config).
"""

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET

# Predictable constraint names, so migrations and error messages can refer to them.
metadata = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_N_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    }
)

VENDOR_CHECK = "vendor IN ('panos', 'fortigate')"
ACTION_CHECK = "action IN ('allow', 'deny', 'drop')"
MATCH_FIELDS = ("src_zones", "dst_zones", "src_addrs", "dst_addrs", "services", "applications")


def _text_array(name: str) -> Column:
    return Column(name, ARRAY(Text), nullable=False)


def _device_fk() -> ForeignKeyConstraint:
    return ForeignKeyConstraint(
        ["vendor", "device"], ["devices.vendor", "devices.device"], ondelete="CASCADE"
    )


devices = Table(
    "devices",
    metadata,
    Column("vendor", Text, nullable=False),
    Column("device", Text, nullable=False),
    Column("loaded_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    PrimaryKeyConstraint("vendor", "device"),
    CheckConstraint(VENDOR_CHECK, name="vendor"),
)

rules = Table(
    "rules",
    metadata,
    Column("id", Text, primary_key=True),  # vendor:device:name, same as Rule.id
    Column("vendor", Text, nullable=False),
    Column("device", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("position", Integer, nullable=False),
    Column("vendor_id", Text),
    *(_text_array(field) for field in MATCH_FIELDS),
    Column("action", Text, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("log", Boolean, nullable=False),
    Column("hit_count", BigInteger),  # as reported by the device; log-based counts are a query
    _device_fk(),
    UniqueConstraint("vendor", "device", "name"),
    UniqueConstraint("vendor", "device", "position"),
    CheckConstraint(ACTION_CHECK, name="action"),
    CheckConstraint("position >= 1", name="position"),
)

address_objects = Table(
    "address_objects",
    metadata,
    Column("vendor", Text, nullable=False),
    Column("device", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("kind", Text, nullable=False),
    Column("value", Text),  # NULL for groups
    _text_array("members"),
    _text_array("resolved"),
    _text_array("unresolved"),
    PrimaryKeyConstraint("vendor", "device", "name"),
    _device_fk(),
    CheckConstraint("kind IN ('ip-netmask', 'ip-range', 'fqdn', 'group')", name="kind"),
)

service_objects = Table(
    "service_objects",
    metadata,
    Column("vendor", Text, nullable=False),
    Column("device", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("is_group", Boolean, nullable=False),
    _text_array("entries"),
    _text_array("members"),
    _text_array("resolved"),
    _text_array("unresolved"),
    PrimaryKeyConstraint("vendor", "device", "name"),
    _device_fk(),
)

# One row per loaded log file; its hash makes reloading the same file a no-op.
log_files = Table(
    "log_files",
    metadata,
    Column("sha256", Text, primary_key=True),
    Column("path", Text, nullable=False),
    Column("events", Integer, nullable=False),
    Column("loaded_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

log_events = Table(
    "log_events",
    metadata,
    Column("id", BigInteger, Identity(), primary_key=True),
    # Deleting a log_files row unloads that file's events.
    Column("log_file", Text, ForeignKey("log_files.sha256", ondelete="CASCADE"), nullable=False),
    Column("vendor", Text, nullable=False),
    Column("device", Text, nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("src_ip", INET, nullable=False),
    Column("dst_ip", INET, nullable=False),
    Column("dst_port", Integer),  # NULL for ICMP
    Column("protocol", Text, nullable=False),
    Column("rule_name", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("bytes", BigInteger, nullable=False),
    CheckConstraint(VENDOR_CHECK, name="vendor"),
    CheckConstraint(ACTION_CHECK, name="action"),
    CheckConstraint("dst_port BETWEEN 0 AND 65535", name="dst_port"),
    CheckConstraint("bytes >= 0", name="bytes"),
    Index(None, "vendor", "device", "rule_name"),  # hit counts per rule
    Index(None, "ts"),  # time-window queries
)

# --- RAG (Step 10) ---------------------------------------------------------------

EMBEDDING_DIMENSIONS = 1024  # Titan Text Embeddings V2 default; the fake embedder matches

# One row per chunk of a best-practice document in data/docs, with its embedding.
doc_chunks = Table(
    "doc_chunks",
    metadata,
    Column("id", Text, primary_key=True),  # "<doc_id>#<chunk_index>"
    Column("doc_id", Text, nullable=False),  # path under data/docs without .md
    Column("chunk_index", Integer, nullable=False),
    Column("title", Text, nullable=False),
    Column("heading", Text, nullable=False),
    Column("vendor", Text, nullable=False),
    Column("text", Text, nullable=False),
    # Re-embed only when the text or the model changes (embedding calls cost money).
    Column("content_sha256", Text, nullable=False),
    Column("embed_model", Text, nullable=False),
    Column("embedding", Vector(EMBEDDING_DIMENSIONS), nullable=False),
    UniqueConstraint("doc_id", "chunk_index"),
    CheckConstraint("vendor IN ('panos', 'fortigate', 'general')", name="vendor"),
    # Approximate nearest-neighbour index for cosine distance. Overkill at a few dozen
    # chunks, but it's what keeps search fast at thousands.
    Index(
        "ix_doc_chunks_embedding",
        "embedding",
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    ),
)
