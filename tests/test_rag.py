"""RAG: chunking, embedders, ingestion and retrieval. No AWS: Bedrock is tested with a
stub client, and the DB tests use the offline FakeEmbedder."""

import io
import json
import math
import shutil
from pathlib import Path

import pytest

from fwlens.db.schema import EMBEDDING_DIMENSIONS
from fwlens.rag import ingest
from fwlens.rag.embed import BedrockEmbedder, FakeEmbedder
from fwlens.rag.ingest import DOCS_DIR, chunk_document, ingest_docs, load_chunks, parse_front_matter
from fwlens.rag.retrieve import format_context, search

DOC = """---
title: Test doc
vendor: general
further_reading: somewhere
---

# Test doc

Intro text that is not part of any section.

## First topic

Alpha paragraph.

## Second topic

Beta paragraph one.

Beta paragraph two.
"""


def write_doc(directory: Path, relative: str, text: str = DOC) -> Path:
    path = directory / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- chunking -----------------------------------------------------------------------


def test_front_matter_is_parsed() -> None:
    meta, body = parse_front_matter(DOC)
    assert meta == {"title": "Test doc", "vendor": "general", "further_reading": "somewhere"}
    assert body.lstrip().startswith("# Test doc")


def test_missing_front_matter_raises() -> None:
    with pytest.raises(ValueError, match="front matter"):
        parse_front_matter("# no header\n")


def test_one_chunk_per_section_with_title_and_heading(tmp_path) -> None:
    chunks = chunk_document(write_doc(tmp_path, "general/test.md"), tmp_path)
    assert [(c.id, c.heading) for c in chunks] == [
        ("general/test#0", "First topic"),
        ("general/test#1", "Second topic"),
    ]
    assert (
        chunks[1].text == "Test doc\n## Second topic\n\nBeta paragraph one.\n\nBeta paragraph two."
    )
    assert "Intro text" not in "".join(c.text for c in chunks)


def test_long_section_splits_on_paragraphs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ingest, "MAX_CHUNK_CHARS", 25)
    chunks = chunk_document(write_doc(tmp_path, "general/test.md"), tmp_path)
    second = [c.text.split("\n\n", 1)[1] for c in chunks if c.heading == "Second topic"]
    assert second == ["Beta paragraph one.", "Beta paragraph two."]


def test_shipped_docs_chunk_cleanly() -> None:
    chunks = load_chunks()
    assert len(chunks) >= 20
    assert {c.vendor for c in chunks} == {"general", "panos", "fortigate"}
    assert len({c.id for c in chunks}) == len(chunks)


# --- embedders ----------------------------------------------------------------------


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


def test_fake_embedder_is_normalized_and_deterministic() -> None:
    [a, b] = FakeEmbedder().embed(["log every allow rule", "log every allow rule"])
    assert len(a) == EMBEDDING_DIMENSIONS
    assert math.isclose(math.sqrt(sum(v * v for v in a)), 1.0)
    assert a == b


def test_fake_embedder_ranks_word_overlap_higher() -> None:
    query, near, far = FakeEmbedder().embed(
        ["shadowed rule order", "a shadowed rule never matches", "retention and NTP time"]
    )
    assert cosine(query, near) > cosine(query, far)


class StubBedrock:
    """Stands in for boto3's bedrock-runtime client."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def invoke_model(self, **kwargs):
        self.calls.append(kwargs)
        payload = json.dumps({"embedding": [0.5] * EMBEDDING_DIMENSIONS})
        return {"body": io.BytesIO(payload.encode())}


def test_bedrock_embedder_request_and_response() -> None:
    stub = StubBedrock()
    vectors = BedrockEmbedder(model_id="amazon.titan-embed-text-v2:0", client=stub).embed(
        ["one", "two"]
    )
    assert len(vectors) == 2 and len(vectors[0]) == EMBEDDING_DIMENSIONS
    assert [c["modelId"] for c in stub.calls] == ["amazon.titan-embed-text-v2:0"] * 2
    assert json.loads(stub.calls[0]["body"]) == {
        "inputText": "one",
        "dimensions": EMBEDDING_DIMENSIONS,
        "normalize": True,
    }


def test_bedrock_model_id_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("BEDROCK_EMBED_MODEL_ID", "custom-model")
    assert BedrockEmbedder(client=StubBedrock()).model_id == "custom-model"


# --- ingestion and search (Postgres) ------------------------------------------------


@pytest.fixture
def docs_copy(tmp_path) -> Path:
    shutil.copytree(DOCS_DIR, tmp_path / "docs")
    return tmp_path / "docs"


@pytest.mark.db
def test_ingest_is_idempotent(conn, docs_copy) -> None:
    total = len(load_chunks(docs_copy))
    first = ingest_docs(conn, FakeEmbedder(), docs_copy)
    second = ingest_docs(conn, FakeEmbedder(), docs_copy)
    assert (first.embedded, first.unchanged, first.removed) == (total, 0, 0)
    assert (second.embedded, second.unchanged, second.removed) == (0, total, 0)


@pytest.mark.db
def test_only_changed_chunks_are_re_embedded(conn, docs_copy) -> None:
    ingest_docs(conn, FakeEmbedder(), docs_copy)
    path = docs_copy / "general" / "logging-and-monitoring.md"
    path.write_text(path.read_text().replace("90 days", "180 days"), encoding="utf-8")
    stats = ingest_docs(conn, FakeEmbedder(), docs_copy)
    assert stats.embedded == 1


@pytest.mark.db
def test_deleted_doc_chunks_are_removed(conn, docs_copy) -> None:
    ingest_docs(conn, FakeEmbedder(), docs_copy)
    removed_doc = docs_copy / "general" / "change-management.md"
    expected = len(chunk_document(removed_doc, docs_copy))
    removed_doc.unlink()
    assert ingest_docs(conn, FakeEmbedder(), docs_copy).removed == expected


@pytest.mark.db
def test_search_finds_the_relevant_section(conn) -> None:
    ingest_docs(conn, FakeEmbedder())
    hits = search(conn, FakeEmbedder(), "logtraffic utm disable logging", k=3, vendor="fortigate")
    assert hits[0].chunk_id == "fortigate/firewall-policy#2"
    assert hits[0].citation == (
        "FortiGate firewall policy best practices > Logging: all, utm and disable "
        "(data/docs/fortigate/firewall-policy.md)"
    )
    assert hits[0].score >= hits[-1].score


@pytest.mark.db
def test_vendor_filter_keeps_general_docs(conn) -> None:
    ingest_docs(conn, FakeEmbedder())
    hits = search(conn, FakeEmbedder(), "rule", k=50, vendor="panos")
    assert {h.vendor for h in hits} == {"panos", "general"}


@pytest.mark.db
def test_search_ignores_vectors_from_other_models(conn) -> None:
    ingest_docs(conn, FakeEmbedder())

    class OtherModel(FakeEmbedder):
        model_id = "some-other-model"

    assert search(conn, OtherModel(), "shadowed rule") == []


@pytest.mark.db
def test_context_is_numbered_for_citation(conn) -> None:
    ingest_docs(conn, FakeEmbedder())
    context = format_context(search(conn, FakeEmbedder(), "shadowed rule", k=2))
    assert context.startswith("[1] ")
    assert "\n\n[2] " in context
