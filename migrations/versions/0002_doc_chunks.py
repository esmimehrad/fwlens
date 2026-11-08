"""pgvector extension and doc_chunks table for RAG over best-practice docs.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Needs a role allowed to create extensions (the compose/CI user is a superuser;
    # on RDS, pgvector is on the allow-list for rds_superuser).
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.create_table(
        "doc_chunks",
        sa.Column("id", sa.Text, nullable=False),
        sa.Column("doc_id", sa.Text, nullable=False),
        sa.Column("chunk_index", sa.Integer, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("heading", sa.Text, nullable=False),
        sa.Column("vendor", sa.Text, nullable=False),
        sa.Column("text", sa.Text, nullable=False),
        sa.Column("content_sha256", sa.Text, nullable=False),
        sa.Column("embed_model", sa.Text, nullable=False),
        sa.Column("embedding", Vector(1024), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_doc_chunks"),
        sa.UniqueConstraint("doc_id", "chunk_index", name="uq_doc_chunks_doc_id_chunk_index"),
        sa.CheckConstraint(
            "vendor IN ('panos', 'fortigate', 'general')", name="ck_doc_chunks_vendor"
        ),
    )
    op.create_index(
        "ix_doc_chunks_embedding",
        "doc_chunks",
        ["embedding"],
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )


def downgrade() -> None:
    op.drop_table("doc_chunks")
    op.execute("DROP EXTENSION IF EXISTS vector")
