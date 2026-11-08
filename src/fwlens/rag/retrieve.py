"""Semantic search over the ingested docs, returning citable hits.

Only chunks embedded with the same model as the query are searched: vectors from two
different models live in different spaces and their distances mean nothing.
"""

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Connection, select

from fwlens.db.schema import doc_chunks
from fwlens.rag.embed import Embedder


class Hit(BaseModel):
    model_config = ConfigDict(frozen=True)

    chunk_id: str  # "<doc_id>#<chunk_index>"
    doc_id: str
    title: str
    heading: str
    vendor: str
    text: str
    score: float  # cosine similarity, 1.0 = same direction

    @property
    def source(self) -> str:
        return f"data/docs/{self.doc_id}.md"

    @property
    def citation(self) -> str:
        return f"{self.title} > {self.heading} ({self.source})"


def search(
    conn: Connection,
    embedder: Embedder,
    query: str,
    k: int = 5,
    vendor: str | None = None,
) -> list[Hit]:
    """Top-k chunks for `query`. With `vendor`, search that vendor's docs plus the
    general ones (vendor-neutral guidance applies everywhere)."""
    [query_vector] = embedder.embed([query])
    distance = doc_chunks.c.embedding.cosine_distance(query_vector)
    statement = (
        select(
            doc_chunks.c.id,
            doc_chunks.c.doc_id,
            doc_chunks.c.title,
            doc_chunks.c.heading,
            doc_chunks.c.vendor,
            doc_chunks.c.text,
            (1 - distance).label("score"),
        )
        .where(doc_chunks.c.embed_model == embedder.model_id)
        .order_by(distance)
        .limit(k)
    )
    if vendor:
        statement = statement.where(doc_chunks.c.vendor.in_([vendor, "general"]))
    return [Hit(chunk_id=row.id, **row._mapping) for row in conn.execute(statement)]


def format_context(hits: list[Hit]) -> str:
    """Numbered sources for an LLM prompt; the model cites them as [1], [2]..."""
    return "\n\n".join(f"[{n}] {hit.citation}\n{hit.text}" for n, hit in enumerate(hits, 1))
