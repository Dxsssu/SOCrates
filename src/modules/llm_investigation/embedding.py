"""Embedding providers used by the module-three semantic retriever."""

from __future__ import annotations

import math
import os
import time
from typing import Callable, Iterable, Protocol

from ...config import LLMInvestigationConfig


EmbeddingVector = tuple[float, ...]


class EmbeddingProvider(Protocol):
    """Convert text batches to fixed-dimensional dense semantic vectors."""

    @property
    def model(self) -> str:
        ...

    @property
    def dimensions(self) -> int:
        ...

    def embed(self, texts: Iterable[str]) -> tuple[EmbeddingVector, ...]:
        """Return one vector per input text, preserving input order."""
        ...


class EmbeddingConfigurationError(RuntimeError):
    """Raised when the embedding service is not configured."""


class EmbeddingResponseError(RuntimeError):
    """Raised when the embedding provider returns an invalid response."""


def normalize_embedding(values: Iterable[float], dimensions: int) -> EmbeddingVector:
    """Validate and L2-normalize a dense vector for cosine search."""

    vector = tuple(float(value) for value in values)
    if len(vector) != dimensions:
        raise EmbeddingResponseError(
            f"embedding dimension mismatch: expected {dimensions}, got {len(vector)}"
        )
    if any(not math.isfinite(value) for value in vector):
        raise EmbeddingResponseError("embedding contains a non-finite value")
    magnitude = math.sqrt(sum(value * value for value in vector))
    if magnitude == 0:
        raise EmbeddingResponseError("embedding vector has zero magnitude")
    return tuple(value / magnitude for value in vector)


class OpenAICompatibleEmbeddingClient:
    """Call an OpenAI-compatible embeddings endpoint with batching and retries."""

    def __init__(
        self,
        config: LLMInvestigationConfig | None = None,
        *,
        api_key: str | None = None,
        session: object | None = None,
        sleeper=time.sleep,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        self.config = config or LLMInvestigationConfig()
        self.api_key = api_key or os.getenv(self.config.embedding_api_key_env)
        if not self.api_key:
            raise EmbeddingConfigurationError(
                "missing embedding API key in environment variable "
                f"{self.config.embedding_api_key_env}"
            )
        if session is None:
            try:
                import requests
            except ImportError as exc:  # pragma: no cover - deployment guard
                raise EmbeddingConfigurationError(
                    "requests is required for the embedding adapter"
                ) from exc
            session = requests.Session()
        self.session = session
        self.sleeper = sleeper
        self.progress_callback = progress_callback
        self.last_request_payloads: list[dict[str, object]] = []

    @property
    def model(self) -> str:
        return self.config.embedding_model

    @property
    def dimensions(self) -> int:
        return self.config.embedding_dimensions

    def _decode(
        self,
        response_data: object,
        expected_count: int,
    ) -> tuple[EmbeddingVector, ...]:
        if not isinstance(response_data, dict):
            raise EmbeddingResponseError("embedding response must be an object")
        data = response_data.get("data")
        if not isinstance(data, list) or len(data) != expected_count:
            raise EmbeddingResponseError(
                "embedding response data length does not match the request"
            )
        indexed: dict[int, EmbeddingVector] = {}
        for fallback_index, item in enumerate(data):
            if not isinstance(item, dict):
                raise EmbeddingResponseError("embedding data item must be an object")
            index = item.get("index", fallback_index)
            embedding = item.get("embedding")
            if not isinstance(index, int) or isinstance(index, bool):
                raise EmbeddingResponseError("embedding index must be an integer")
            if not isinstance(embedding, list):
                raise EmbeddingResponseError("embedding must be an array")
            if index in indexed or not 0 <= index < expected_count:
                raise EmbeddingResponseError("embedding response index is invalid")
            try:
                indexed[index] = normalize_embedding(embedding, self.dimensions)
            except (TypeError, ValueError) as exc:
                raise EmbeddingResponseError(
                    "embedding contains a non-numeric value"
                ) from exc
        if set(indexed) != set(range(expected_count)):
            raise EmbeddingResponseError("embedding response indices are incomplete")
        return tuple(indexed[index] for index in range(expected_count))

    def _embed_batch(self, texts: tuple[str, ...]) -> tuple[EmbeddingVector, ...]:
        payload: dict[str, object] = {
            "model": self.model,
            "input": list(texts),
            "dimensions": self.dimensions,
        }
        self.last_request_payloads.append(payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        last_error: Exception | None = None
        for attempt in range(self.config.embedding_max_retries + 1):
            try:
                response = self.session.post(
                    self.config.embedding_api_url,
                    headers=headers,
                    json=payload,
                    timeout=self.config.embedding_timeout_seconds,
                )
                response.raise_for_status()
                return self._decode(response.json(), len(texts))
            except Exception as exc:
                last_error = exc
            if (
                attempt < self.config.embedding_max_retries
                and self.config.embedding_retry_backoff_seconds
            ):
                self.sleeper(
                    self.config.embedding_retry_backoff_seconds * (2**attempt)
                )
        assert last_error is not None
        if isinstance(last_error, EmbeddingResponseError):
            raise last_error
        raise EmbeddingResponseError(
            f"embedding request failed: {type(last_error).__name__}"
        ) from last_error

    def embed(self, texts: Iterable[str]) -> tuple[EmbeddingVector, ...]:
        values = tuple(
            str(text)[: self.config.embedding_max_input_characters] for text in texts
        )
        if not values:
            return ()
        results: list[EmbeddingVector] = []
        batch_size = self.config.embedding_batch_size
        for start in range(0, len(values), batch_size):
            results.extend(self._embed_batch(values[start : start + batch_size]))
            if self.progress_callback is not None:
                self.progress_callback(
                    min(start + batch_size, len(values)),
                    len(values),
                )
        return tuple(results)
