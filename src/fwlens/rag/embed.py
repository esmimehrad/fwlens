"""Text embedders: Amazon Titan on Bedrock for real use, a hashing fake for tests.

Both produce EMBEDDING_DIMENSIONS-long, L2-normalized vectors and carry a model_id that
is stored next to every embedding, so vectors from different models never get compared.
"""

import hashlib
import json
import math
import os
import re
from typing import Any, Protocol

from fwlens.db.schema import EMBEDDING_DIMENSIONS

DEFAULT_BEDROCK_MODEL = "amazon.titan-embed-text-v2:0"


class Embedder(Protocol):
    model_id: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class BedrockEmbedder:
    """Amazon Titan Text Embeddings V2 via the Bedrock runtime API.

    Credentials and region come from the standard AWS chain (AWS_PROFILE, AWS_REGION,
    ~/.aws/config); nothing secret is read or stored here. Titan V2 embeds one text per
    request, so this makes len(texts) calls.
    """

    def __init__(self, model_id: str | None = None, client: Any = None) -> None:
        self.model_id = model_id or os.environ.get("BEDROCK_EMBED_MODEL_ID", DEFAULT_BEDROCK_MODEL)
        if client is None:
            import boto3  # imported lazily so tests and offline use don't need AWS

            client = boto3.client("bedrock-runtime")
        self._client = client

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            response = self._client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(
                    {"inputText": text, "dimensions": EMBEDDING_DIMENSIONS, "normalize": True}
                ),
            )
            vectors.append(json.loads(response["body"].read())["embedding"])
        return vectors


class FakeEmbedder:
    """Deterministic, offline "embedding": hashed bag of words (feature hashing).

    It only captures word overlap, not meaning, but that's enough to test ingestion and
    ranking without AWS. Its model_id keeps its vectors apart from real ones.
    """

    model_id = "fake-hashing-v1"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    @staticmethod
    def _embed_one(text: str) -> list[float]:
        vector = [0.0] * EMBEDDING_DIMENSIONS
        for word in re.findall(r"[a-z0-9]+", text.lower()):
            digest = hashlib.sha256(word.encode()).digest()
            bucket = int.from_bytes(digest[:4], "big") % EMBEDDING_DIMENSIONS
            vector[bucket] += 1.0 if digest[4] % 2 else -1.0  # random sign limits collisions
        norm = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [v / norm for v in vector]


def get_embedder(fake: bool = False) -> Embedder:
    """The embedder to use: the fake one if asked (or FWLENS_EMBEDDER=fake), else Bedrock."""
    if fake or os.environ.get("FWLENS_EMBEDDER") == "fake":
        return FakeEmbedder()
    return BedrockEmbedder()
