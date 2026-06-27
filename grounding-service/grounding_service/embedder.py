"""Embedding backends behind a Protocol so tests stay offline (FakeEmbedder)."""
from __future__ import annotations

import hashlib
import math
from typing import Protocol, runtime_checkable


@runtime_checkable
class Embedder(Protocol):
    @property
    def dim(self) -> int: ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class FakeEmbedder:
    """Deterministic, offline embedder for tests. Same text -> same unit vector."""

    def __init__(self, dim: int = 8) -> None:
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def _one(self, text: str) -> list[float]:
        out: list[float] = []
        for i in range(self._dim):
            h = hashlib.sha256(f"{i}:{text}".encode("utf-8")).digest()
            out.append(int.from_bytes(h[:4], "big") / 2**32)
        norm = math.sqrt(sum(x * x for x in out)) or 1.0
        return [x / norm for x in out]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]


class BgeEmbedder:
    """Production embedder via fastembed (bge-small-en-v1.5). Model loads lazily."""

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        self._model_name = model_name
        self._model = None
        self._dim = 384  # bge-small-en-v1.5

    @property
    def dim(self) -> int:
        return self._dim

    def _ensure(self) -> None:
        if self._model is None:
            from fastembed import TextEmbedding

            self._model = TextEmbedding(model_name=self._model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        self._ensure()
        assert self._model is not None
        return [list(map(float, v)) for v in self._model.embed(texts)]
