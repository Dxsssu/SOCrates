"""False-positive knowledge construction and retrieval contracts."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Mapping, Protocol

import numpy as np

from ...config import LLMInvestigationConfig
from ...models import (
    AlertObject,
    KnowledgePattern,
    NormalizedAlert,
)
from ..benign_fingerprint import (
    PayloadAttributeTemplateExtractor,
)
from .embedding import EmbeddingProvider, EmbeddingVector, normalize_embedding


class FalsePositiveKnowledgeBase(Protocol):
    """Store and retrieve environment-specific benign patterns."""

    def build(self, confirmed_false_positives: Iterable[NormalizedAlert]) -> None:
        """Cluster confirmed false positives and construct knowledge entries."""
        ...

    def retrieve(self, alert: AlertObject) -> tuple[KnowledgePattern, ...]:
        """Perform structured filtering followed by semantic retrieval."""
        ...

    def retrieve_many(
        self,
        alerts: Iterable[AlertObject],
    ) -> tuple[tuple[KnowledgePattern, ...], ...]:
        """Retrieve semantic knowledge for a batch of query alerts."""
        ...


def _services(alert: AlertObject) -> tuple[str, ...]:
    if isinstance(alert, NormalizedAlert):
        return (alert.service,) if alert.service else ()
    return alert.services


VECTOR_DATABASE_FORMAT = "socrates-embedding-rag-sqlite"
VECTOR_DATABASE_VERSION = 1
EMBEDDING_TEXT_VERSION = 1
FORBIDDEN_LABEL_FIELDS = {
    "label",
    "event_label",
    "time_label",
    "triage_label",
    "has_attack_event_label",
}


class KnowledgeVectorStoreError(RuntimeError):
    """Raised when a persistent embedding knowledge base is invalid."""


@dataclass(frozen=True, slots=True)
class _VectorEntry:
    pattern: KnowledgePattern
    alert_source: str
    alert_semantics: str
    services: tuple[str, ...]
    support: int
    embedding: EmbeddingVector


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    """A validated knowledge pattern ready for vectorization and storage."""

    pattern: KnowledgePattern
    alert_source: str
    alert_semantics: str
    services: tuple[str, ...]
    support: int


def _without_labels(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _without_labels(item)
            for key, item in value.items()
            if str(key).casefold() not in FORBIDDEN_LABEL_FIELDS
        }
    if isinstance(value, (list, tuple, set)):
        return [_without_labels(item) for item in value]
    return value


class EmbeddingFalsePositiveKnowledgeBase:
    """Dense-vector RAG knowledge base with optional durable SQLite storage."""

    def __init__(
        self,
        embedder: EmbeddingProvider,
        config: LLMInvestigationConfig | None = None,
        *,
        template_extractor: PayloadAttributeTemplateExtractor | None = None,
    ) -> None:
        self.config = config or LLMInvestigationConfig()
        self.embedder = embedder
        if embedder.dimensions != self.config.embedding_dimensions:
            raise ValueError("embedding provider dimensions do not match configuration")
        if embedder.model != self.config.embedding_model:
            raise ValueError("embedding provider model does not match configuration")
        self.template_extractor = (
            template_extractor
            or PayloadAttributeTemplateExtractor(
                max_value_characters=self.config.max_field_characters,
                max_template_characters=self.config.embedding_max_input_characters // 2,
                numeric_min_digits=3,
            )
        )
        self._entries: tuple[_VectorEntry, ...] = ()
        self._embedding_matrix = np.empty(
            (0, self.embedder.dimensions),
            dtype=np.float32,
        )
        self._semantic_alias_group: dict[str, int] = {}
        for group_index, group in enumerate(
            self.config.retrieval_semantic_alias_groups
        ):
            for semantic in group:
                self._semantic_alias_group[self._normalize_semantics(semantic)] = (
                    group_index
                )
        self._semantic_group_members: dict[int, tuple[str, ...]] = {
            group_index: tuple(
                self._normalize_semantics(semantic) for semantic in group
            )
            for group_index, group in enumerate(
                self.config.retrieval_semantic_alias_groups
            )
        }
        self._semantic_entry_indices: dict[str, tuple[int, ...]] = {}
        self.database_path = (
            Path(self.config.knowledge_database_path).expanduser()
            if self.config.knowledge_database_path is not None
            else None
        )
        self.status = "not_built"

    @staticmethod
    def _normalize_semantics(value: str) -> str:
        return " ".join(value.split()).casefold()

    def _set_entries(self, entries: Iterable[_VectorEntry]) -> None:
        self._entries = tuple(entries)
        self._embedding_matrix = np.asarray(
            [entry.embedding for entry in self._entries],
            dtype=np.float32,
        )
        expected_shape = (len(self._entries), self.embedder.dimensions)
        if self._embedding_matrix.shape != expected_shape:
            raise KnowledgeVectorStoreError(
                "knowledge embedding matrix has an invalid shape"
            )
        grouped_indices: dict[str, list[int]] = defaultdict(list)
        for index, entry in enumerate(self._entries):
            grouped_indices[
                self._normalize_semantics(entry.alert_semantics)
            ].append(index)
        self._semantic_entry_indices = {
            semantic: tuple(indices)
            for semantic, indices in grouped_indices.items()
        }

    def _eligible_entry_indices(self, query_semantics: str) -> tuple[int, ...]:
        normalized = self._normalize_semantics(query_semantics)
        group_index = self._semantic_alias_group.get(normalized)
        compatible = (
            self._semantic_group_members[group_index]
            if group_index is not None
            else (normalized,)
        )
        return tuple(
            index
            for semantic in compatible
            for index in self._semantic_entry_indices.get(semantic, ())
        )

    def _template(self, alert: AlertObject) -> str:
        if isinstance(alert, NormalizedAlert):
            clean = replace(
                alert,
                attributes=_without_labels(alert.attributes),  # type: ignore[arg-type]
            )
            return self.template_extractor.extract(clean)
        return json.dumps(
            _without_labels(alert.statistics),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

    def _payload_embedding_text(self, alert: AlertObject) -> str:
        """Return only the normalized payload used inside a semantics bucket."""

        return (self._template(alert) or "<EMPTY>")[
            : self.config.embedding_max_input_characters
        ]

    def _documents(
        self,
        alerts: Iterable[NormalizedAlert],
    ) -> tuple[tuple[KnowledgeDocument, ...], str]:
        grouped: dict[
            tuple[str, str, tuple[str, ...], str],
            list[NormalizedAlert],
        ] = defaultdict(list)
        for alert in alerts:
            services = tuple(sorted(service.casefold() for service in _services(alert)))
            key = (
                alert.alert_source.casefold(),
                alert.alert_semantics.casefold(),
                services,
                self._template(alert),
            )
            grouped[key].append(alert)

        documents: list[KnowledgeDocument] = []
        corpus_hasher = hashlib.sha256()
        for key, grouped_alerts in sorted(grouped.items()):
            ordered = sorted(
                grouped_alerts,
                key=lambda item: (item.timestamp, item.alert_id),
            )
            representative = ordered[0]
            index_text = self._payload_embedding_text(representative)
            identity = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
            pattern = KnowledgePattern(
                pattern_id=f"vec-fp-{digest}",
                index_text=index_text,
                pattern_text=(
                    "历史环境良性模式："
                    f"来源={representative.alert_source}；"
                    f"语义={representative.alert_semantics}；"
                    f"服务={list(_services(representative))}；"
                    f"支持度={len(ordered)}；"
                    f"规范化载荷模板={key[3]}。"
                ),
                provenance=tuple(alert.alert_id for alert in ordered[:20]),
            )
            documents.append(
                KnowledgeDocument(
                    pattern=pattern,
                    alert_source=key[0],
                    alert_semantics=key[1],
                    services=key[2],
                    support=len(ordered),
                )
            )
            corpus_hasher.update(identity.encode("utf-8"))
            corpus_hasher.update(str(len(ordered)).encode("ascii"))
            for alert in ordered:
                corpus_hasher.update(alert.alert_id.encode("utf-8"))
        if not documents:
            raise ValueError("embedding knowledge base requires at least one alert")
        return tuple(documents), corpus_hasher.hexdigest()

    def _index_signature(self) -> str:
        payload = {
            "text_version": EMBEDDING_TEXT_VERSION,
            "model": self.embedder.model,
            "dimensions": self.embedder.dimensions,
            "max_input_characters": self.config.embedding_max_input_characters,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _pack(vector: EmbeddingVector) -> bytes:
        return struct.pack(f"<{len(vector)}f", *vector)

    def _unpack(self, value: object) -> EmbeddingVector:
        if not isinstance(value, bytes):
            raise KnowledgeVectorStoreError("stored embedding must be a BLOB")
        expected_bytes = self.embedder.dimensions * 4
        if len(value) != expected_bytes:
            raise KnowledgeVectorStoreError(
                "stored embedding byte length does not match configured dimensions"
            )
        values = struct.unpack(f"<{self.embedder.dimensions}f", value)
        return normalize_embedding(values, self.embedder.dimensions)

    def _load(self, corpus_signature: str) -> bool:
        if self.database_path is None or not self.database_path.exists():
            return False
        try:
            connection = sqlite3.connect(self.database_path, timeout=30.0)
            connection.row_factory = sqlite3.Row
            try:
                metadata = {
                    row["key"]: row["value"]
                    for row in connection.execute("SELECT key, value FROM rag_metadata")
                }
                expected = {
                    "format": VECTOR_DATABASE_FORMAT,
                    "version": str(VECTOR_DATABASE_VERSION),
                    "index_signature": self._index_signature(),
                }
                for key, value in expected.items():
                    if metadata.get(key) != value:
                        raise KnowledgeVectorStoreError(
                            f"vector knowledge database {key} is incompatible"
                        )
                if metadata.get("corpus_signature") != corpus_signature:
                    return False
                rows = tuple(
                    connection.execute("SELECT * FROM rag_patterns ORDER BY pattern_id")
                )
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise KnowledgeVectorStoreError(
                f"cannot read vector knowledge database: {self.database_path}"
            ) from exc
        if not rows:
            raise KnowledgeVectorStoreError(
                "vector knowledge database contains no patterns"
            )
        entries: list[_VectorEntry] = []
        for row in rows:
            try:
                services = tuple(json.loads(row["services_json"]))
                provenance = tuple(json.loads(row["provenance_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise KnowledgeVectorStoreError(
                    "vector knowledge metadata JSON is invalid"
                ) from exc
            if not all(isinstance(value, str) for value in (*services, *provenance)):
                raise KnowledgeVectorStoreError(
                    "vector knowledge metadata must contain strings"
                )
            pattern = KnowledgePattern(
                pattern_id=row["pattern_id"],
                index_text=row["index_text"],
                pattern_text=row["pattern_text"],
                provenance=provenance,
            )
            entries.append(
                _VectorEntry(
                    pattern=pattern,
                    alert_source=row["alert_source"],
                    alert_semantics=row["alert_semantics"],
                    services=services,
                    support=row["support"],
                    embedding=self._unpack(row["embedding"]),
                )
            )
        self._set_entries(entries)
        self.status = "loaded"
        return True

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE rag_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE rag_patterns (
                pattern_id TEXT PRIMARY KEY,
                alert_source TEXT NOT NULL,
                alert_semantics TEXT NOT NULL,
                services_json TEXT NOT NULL,
                index_text TEXT NOT NULL,
                pattern_text TEXT NOT NULL,
                support INTEGER NOT NULL CHECK (support >= 1),
                provenance_json TEXT NOT NULL,
                embedding BLOB NOT NULL,
                embedding_dimensions INTEGER NOT NULL
            );

            CREATE INDEX idx_rag_patterns_metadata
                ON rag_patterns(alert_source, alert_semantics);
            """
        )

    def _save(
        self,
        documents: tuple[KnowledgeDocument, ...],
        embeddings: tuple[EmbeddingVector, ...],
        corpus_signature: str,
        build_mode: str,
    ) -> None:
        if self.database_path is None:
            return
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.database_path.name}.",
            suffix=".tmp",
            dir=self.database_path.parent,
        )
        os.close(descriptor)
        metadata = {
            "format": VECTOR_DATABASE_FORMAT,
            "version": str(VECTOR_DATABASE_VERSION),
            "index_signature": self._index_signature(),
            "corpus_signature": corpus_signature,
            "build_mode": build_mode,
            "embedding_model": self.embedder.model,
            "embedding_dimensions": str(self.embedder.dimensions),
            "pattern_count": str(len(documents)),
        }
        try:
            connection = sqlite3.connect(temporary_name, timeout=30.0)
            try:
                connection.execute("PRAGMA synchronous = FULL")
                with connection:
                    self._create_schema(connection)
                    connection.executemany(
                        "INSERT INTO rag_metadata(key, value) VALUES (?, ?)",
                        tuple(sorted(metadata.items())),
                    )
                    connection.executemany(
                        """
                        INSERT INTO rag_patterns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            (
                                document.pattern.pattern_id,
                                document.alert_source,
                                document.alert_semantics,
                                json.dumps(document.services, ensure_ascii=False),
                                document.pattern.index_text,
                                document.pattern.pattern_text,
                                document.support,
                                json.dumps(
                                    document.pattern.provenance,
                                    ensure_ascii=False,
                                ),
                                self._pack(embedding),
                                self.embedder.dimensions,
                            )
                            for document, embedding in zip(
                                documents,
                                embeddings,
                                strict=True,
                            )
                        ),
                    )
            finally:
                connection.close()
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.database_path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _document_corpus_signature(
        documents: tuple[KnowledgeDocument, ...],
    ) -> str:
        hasher = hashlib.sha256()
        for document in documents:
            material = {
                "pattern_id": document.pattern.pattern_id,
                "index_text": document.pattern.index_text,
                "pattern_text": document.pattern.pattern_text,
                "provenance": document.pattern.provenance,
                "alert_source": document.alert_source,
                "alert_semantics": document.alert_semantics,
                "services": document.services,
                "support": document.support,
            }
            hasher.update(
                json.dumps(
                    material,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        return hasher.hexdigest()

    @staticmethod
    def _validate_documents(
        documents: tuple[KnowledgeDocument, ...],
    ) -> None:
        if not documents:
            raise ValueError("embedding knowledge base requires at least one document")
        pattern_ids = [document.pattern.pattern_id for document in documents]
        if len(pattern_ids) != len(set(pattern_ids)):
            raise ValueError("knowledge documents contain duplicate pattern IDs")
        for document in documents:
            if document.support < 1:
                raise ValueError("knowledge document support must be positive")
            if not document.pattern.pattern_id.strip():
                raise ValueError("knowledge pattern ID cannot be blank")
            if not document.pattern.index_text.strip():
                raise ValueError("knowledge pattern index text cannot be blank")
            if not document.pattern.pattern_text.strip():
                raise ValueError("knowledge pattern text cannot be blank")
            if not document.alert_source.strip():
                raise ValueError("knowledge document alert source cannot be blank")
            if not document.alert_semantics.strip():
                raise ValueError("knowledge document alert semantics cannot be blank")

    def _build_documents(
        self,
        documents: tuple[KnowledgeDocument, ...],
        corpus_signature: str,
        *,
        build_mode: str,
    ) -> None:
        self._validate_documents(documents)
        if self._load(corpus_signature):
            return
        embeddings = self.embedder.embed(
            document.pattern.index_text for document in documents
        )
        if len(embeddings) != len(documents):
            raise KnowledgeVectorStoreError(
                "embedding provider did not return one vector per knowledge pattern"
            )
        normalized = tuple(
            normalize_embedding(embedding, self.embedder.dimensions)
            for embedding in embeddings
        )
        self._set_entries(
            _VectorEntry(
                pattern=document.pattern,
                alert_source=document.alert_source,
                alert_semantics=document.alert_semantics,
                services=document.services,
                support=document.support,
                embedding=embedding,
            )
            for document, embedding in zip(documents, normalized, strict=True)
        )
        previous_exists = self.database_path is not None and self.database_path.exists()
        self._save(documents, normalized, corpus_signature, build_mode)
        self.status = "rebuilt" if previous_exists else "created"
        if self.database_path is None:
            self.status = "in_memory"

    def build_documents(
        self,
        documents: Iterable[KnowledgeDocument],
    ) -> None:
        """Vectorize and store externally synthesized knowledge patterns."""

        document_batch = tuple(documents)
        corpus_signature = self._document_corpus_signature(document_batch)
        self._build_documents(
            document_batch,
            corpus_signature,
            build_mode="llm_assisted_documents",
        )

    def load_prebuilt_documents(self) -> bool:
        """Load an LLM-assisted database without replacing its training corpus."""

        if self.database_path is None or not self.database_path.exists():
            return False
        try:
            with sqlite3.connect(self.database_path, timeout=30.0) as connection:
                metadata = dict(
                    connection.execute("SELECT key, value FROM rag_metadata")
                )
        except sqlite3.DatabaseError as exc:
            raise KnowledgeVectorStoreError(
                f"cannot read vector knowledge database: {self.database_path}"
            ) from exc
        if metadata.get("build_mode") != "llm_assisted_documents":
            return False
        corpus_signature = metadata.get("corpus_signature")
        if not corpus_signature:
            raise KnowledgeVectorStoreError(
                "prebuilt vector knowledge database has no corpus signature"
            )
        return self._load(corpus_signature)

    def build(self, confirmed_false_positives: Iterable[NormalizedAlert]) -> None:
        documents, corpus_signature = self._documents(confirmed_false_positives)
        self._build_documents(
            documents,
            corpus_signature,
            build_mode="deterministic_alert_documents",
        )

    def _rank_scores(
        self,
        scores: np.ndarray,
        entry_indices: tuple[int, ...],
    ) -> tuple[KnowledgePattern, ...]:
        # The score array is already restricted to the selected semantics bucket.
        # Stable sorting plus insertion order makes equal scores deterministic.
        ranked_indices = np.argsort(-scores, kind="stable")
        accepted: list[KnowledgePattern] = []
        for raw_local_index in ranked_indices:
            local_index = int(raw_local_index)
            index = entry_indices[local_index]
            similarity = float(scores[local_index])
            if similarity < self.config.retrieval_similarity_threshold:
                break
            accepted.append(
                replace(self._entries[index].pattern, similarity=similarity)
            )
            if len(accepted) == self.config.retrieval_top_k:
                break
        return tuple(accepted)

    def retrieve_many(
        self,
        alerts: Iterable[AlertObject],
    ) -> tuple[tuple[KnowledgePattern, ...], ...]:
        alert_batch = tuple(alerts)
        if not alert_batch:
            return ()
        if not self._entries:
            raise KnowledgeVectorStoreError("embedding knowledge base is not built")
        eligible_by_position = tuple(
            self._eligible_entry_indices(alert.alert_semantics)
            for alert in alert_batch
        )
        searchable_positions = tuple(
            index
            for index, eligible in enumerate(eligible_by_position)
            if eligible
        )
        if not searchable_positions:
            return tuple(() for _ in alert_batch)
        embeddings = self.embedder.embed(
            self._payload_embedding_text(alert_batch[index])
            for index in searchable_positions
        )
        if len(embeddings) != len(searchable_positions):
            raise KnowledgeVectorStoreError(
                "embedding provider did not return one vector per searchable alert"
            )
        retrieved: list[tuple[KnowledgePattern, ...]] = [()] * len(alert_batch)
        for position, embedding in zip(
            searchable_positions,
            embeddings,
            strict=True,
        ):
            normalized_query = np.asarray(
                normalize_embedding(embedding, self.embedder.dimensions),
                dtype=np.float32,
            )
            entry_indices = eligible_by_position[position]
            semantic_matrix = self._embedding_matrix[
                np.asarray(entry_indices, dtype=np.intp)
            ]
            scores = semantic_matrix @ normalized_query
            retrieved[position] = self._rank_scores(scores, entry_indices)
        return tuple(retrieved)

    def retrieve(self, alert: AlertObject) -> tuple[KnowledgePattern, ...]:
        return self.retrieve_many((alert,))[0]

    def __len__(self) -> int:
        return len(self._entries)
