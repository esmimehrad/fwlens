"""Initial schema: devices, rules, address/service objects, log files and events.

Written by hand and self-contained (it does not import fwlens.db.schema), so it keeps
creating the same tables even after schema.py moves on. A test checks the two agree.

Revision ID: 0001
Revises:
Create Date: 2026-11-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, INET

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

VENDOR_CHECK = "vendor IN ('panos', 'fortigate')"
ACTION_CHECK = "action IN ('allow', 'deny', 'drop')"


def _text_array(name: str) -> sa.Column:
    return sa.Column(name, ARRAY(sa.Text), nullable=False)


def _device_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["vendor", "device"],
        ["devices.vendor", "devices.device"],
        name=f"fk_{table}_vendor_device_devices",
        ondelete="CASCADE",
    )


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("vendor", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column(
            "loaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("vendor", "device", name="pk_devices"),
        sa.CheckConstraint(VENDOR_CHECK, name="ck_devices_vendor"),
    )

    op.create_table(
        "rules",
        sa.Column("id", sa.Text, nullable=False),
        sa.Column("vendor", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("position", sa.Integer, nullable=False),
        sa.Column("vendor_id", sa.Text),
        _text_array("src_zones"),
        _text_array("dst_zones"),
        _text_array("src_addrs"),
        _text_array("dst_addrs"),
        _text_array("services"),
        _text_array("applications"),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("log", sa.Boolean, nullable=False),
        sa.Column("hit_count", sa.BigInteger),
        sa.PrimaryKeyConstraint("id", name="pk_rules"),
        _device_fk("rules"),
        sa.UniqueConstraint("vendor", "device", "name", name="uq_rules_vendor_device_name"),
        sa.UniqueConstraint("vendor", "device", "position", name="uq_rules_vendor_device_position"),
        sa.CheckConstraint(ACTION_CHECK, name="ck_rules_action"),
        sa.CheckConstraint("position >= 1", name="ck_rules_position"),
    )

    op.create_table(
        "address_objects",
        sa.Column("vendor", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("value", sa.Text),
        _text_array("members"),
        _text_array("resolved"),
        _text_array("unresolved"),
        sa.PrimaryKeyConstraint("vendor", "device", "name", name="pk_address_objects"),
        _device_fk("address_objects"),
        sa.CheckConstraint(
            "kind IN ('ip-netmask', 'ip-range', 'fqdn', 'group')", name="ck_address_objects_kind"
        ),
    )

    op.create_table(
        "service_objects",
        sa.Column("vendor", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("is_group", sa.Boolean, nullable=False),
        _text_array("entries"),
        _text_array("members"),
        _text_array("resolved"),
        _text_array("unresolved"),
        sa.PrimaryKeyConstraint("vendor", "device", "name", name="pk_service_objects"),
        _device_fk("service_objects"),
    )

    op.create_table(
        "log_files",
        sa.Column("sha256", sa.Text, nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("events", sa.Integer, nullable=False),
        sa.Column(
            "loaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("sha256", name="pk_log_files"),
    )

    op.create_table(
        "log_events",
        sa.Column("id", sa.BigInteger, sa.Identity(), nullable=False),
        sa.Column("log_file", sa.Text, nullable=False),
        sa.Column("vendor", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", INET, nullable=False),
        sa.Column("dst_ip", INET, nullable=False),
        sa.Column("dst_port", sa.Integer),
        sa.Column("protocol", sa.Text, nullable=False),
        sa.Column("rule_name", sa.Text, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("bytes", sa.BigInteger, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_log_events"),
        sa.ForeignKeyConstraint(
            ["log_file"],
            ["log_files.sha256"],
            name="fk_log_events_log_file_log_files",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(VENDOR_CHECK, name="ck_log_events_vendor"),
        sa.CheckConstraint(ACTION_CHECK, name="ck_log_events_action"),
        sa.CheckConstraint("dst_port BETWEEN 0 AND 65535", name="ck_log_events_dst_port"),
        sa.CheckConstraint("bytes >= 0", name="ck_log_events_bytes"),
    )
    op.create_index(
        "ix_log_events_vendor_device_rule_name", "log_events", ["vendor", "device", "rule_name"]
    )
    op.create_index("ix_log_events_ts", "log_events", ["ts"])


def downgrade() -> None:
    # Reverse order: children before the tables they reference.
    op.drop_table("log_events")
    op.drop_table("log_files")
    op.drop_table("service_objects")
    op.drop_table("address_objects")
    op.drop_table("rules")
    op.drop_table("devices")
