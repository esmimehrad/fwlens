"""Chunk the best-practice docs in data/docs and store their embeddings in pgvector.

Docs are markdown with a small front matter block (title, vendor, further_reading).
Chunks follow the "## " sections, so each one is a self-contained topic that can be
cited by heading; a long section is split further on paragraph boundaries.

Ingestion is idempotent and frugal: a chunk is (re-)embedded only when its text or the
embedding model changed, and chunks of deleted or shortened docs are removed.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Connection, delete, select
from sqlalchemy.dialects.postgresql import insert

from fwlens.db.schema import doc_chunks
from fwlens.rag.embed import Embedder

DOCS_DIR = Path(__file__).resolve().parents[3] / "data" / "docs"
MAX_CHUNK_CHARS = 1500  # well under Titan V2's input limit; keeps citations focused


@dataclass(frozen=True)
class Chunk:
    doc_id: str
    chunk_index: int
    title: str
    heading: str
    vendor: str
    text: str  # what gets embedded and returned: title and heading included for context

    @property
    def id(self) -> str:
        return f"{self.doc_id}#{self.chunk_index}"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()


@dataclass(frozen=True)
class IngestStats:
    embedded: int
    unchanged: int
    removed: int


def parse_front_matter(markdown: str) -> tuple[dict[str, str], str]:
    """Split "---\\nkey: value\\n---\\nbody" into ({key: value}, body)."""
    if not markdown.startswith("---\n"):
        raise ValueError("doc must start with a --- front matter block")
    header, _, body = markdown[4:].partition("\n---\n")
    meta = {}
    for line in header.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"bad front matter line: {line!r}")
        meta[key.strip()] = value.strip()
    return meta, body


def chunk_document(path: Path, docs_dir: Path = DOCS_DIR) -> list[Chunk]:
    meta, body = parse_front_matter(path.read_text(encoding="utf-8"))
    for key in ("title", "vendor"):
        if key not in meta:
            raise ValueError(f"{path.name}: front matter needs {key!r}")
    doc_id = path.relative_to(docs_dir).with_suffix("").as_posix()

    chunks: list[Chunk] = []
    for heading, section in _sections(body):
        for piece in _split_long(section):
            text = f"{meta['title']}\n## {heading}\n\n{piece}"
            chunks.append(Chunk(doc_id, len(chunks), meta["title"], heading, meta["vendor"], text))
    return chunks


def _sections(body: str) -> list[tuple[str, str]]:
    """[(heading, text)] for each "## " section; text before the first one is skipped
    (it's the "# title" line and the provenance note)."""
    sections: list[tuple[str, str]] = []
    heading, lines = None, []
    for line in body.splitlines():
        if line.startswith("## "):
            if heading is not None:
                sections.append((heading, "\n".join(lines).strip()))
            heading, lines = line[3:].strip(), []
        else:
            lines.append(line)
    if heading is not None:
        sections.append((heading, "\n".join(lines).strip()))
    return [(h, t) for h, t in sections if t]


def _split_long(text: str) -> list[str]:
    """Greedily pack paragraphs into pieces of at most MAX_CHUNK_CHARS (a single longer
    paragraph stays whole rather than being cut mid-sentence)."""
    pieces, current = [], ""
    for paragraph in text.split("\n\n"):
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if current and len(candidate) > MAX_CHUNK_CHARS:
            pieces.append(current)
            current = paragraph
        else:
            current = candidate
    return [*pieces, current] if current else pieces


def load_chunks(docs_dir: Path = DOCS_DIR) -> list[Chunk]:
    return [c for path in sorted(docs_dir.rglob("*.md")) for c in chunk_document(path, docs_dir)]


def ingest_docs(conn: Connection, embedder: Embedder, docs_dir: Path = DOCS_DIR) -> IngestStats:
    chunks = load_chunks(docs_dir)
    stored = {
        row.id: (row.content_sha256, row.embed_model)
        for row in conn.execute(
            select(doc_chunks.c.id, doc_chunks.c.content_sha256, doc_chunks.c.embed_model)
        )
    }
    todo = [c for c in chunks if stored.get(c.id) != (c.sha256, embedder.model_id)]

    if todo:
        vectors = embedder.embed([c.text for c in todo])
        rows = [
            {
                "id": c.id,
                "doc_id": c.doc_id,
                "chunk_index": c.chunk_index,
                "title": c.title,
                "heading": c.heading,
                "vendor": c.vendor,
                "text": c.text,
                "content_sha256": c.sha256,
                "embed_model": embedder.model_id,
                "embedding": vector,
            }
            for c, vector in zip(todo, vectors, strict=True)
        ]
        statement = insert(doc_chunks)
        conn.execute(
            statement.on_conflict_do_update(
                index_elements=[doc_chunks.c.id],
                set_={col: statement.excluded[col] for col in rows[0] if col != "id"},
            ),
            rows,
        )

    current_ids = {c.id for c in chunks}
    stale = [chunk_id for chunk_id in stored if chunk_id not in current_ids]
    if stale:
        conn.execute(delete(doc_chunks).where(doc_chunks.c.id.in_(stale)))

    return IngestStats(embedded=len(todo), unchanged=len(chunks) - len(todo), removed=len(stale))
