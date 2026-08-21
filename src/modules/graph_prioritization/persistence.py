"""Durable storage for module-two alert/entity graphs."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol

from ...config import GraphPrioritizationConfig
from ...models import (
    AlertObject,
    GraphPersistenceInfo,
    GraphPrioritizationResult,
    MetaAlert,
    NormalizedAlert,
    alert_object_entities,
    alert_object_id,
)
from .pattern import GraphAlertPatternExtractor, alert_ports


DATABASE_FORMAT = "socrates-alert-graph-sqlite"
DATABASE_VERSION = 2
FORBIDDEN_LABEL_FIELDS = {
    "label",
    "event_label",
    "time_label",
    "triage_label",
    "has_attack_event_label",
}


class AlertGraphPersistenceError(RuntimeError):
    """Raised when the module-two graph cannot be safely persisted."""


class AlertGraphStore(Protocol):
    """Replaceable persistence interface for one module-two graph result."""

    @property
    def path(self) -> Path:
        ...

    def save(self, result: GraphPrioritizationResult) -> GraphPersistenceInfo:
        """Atomically replace the durable graph with ``result``."""
        ...


def _configuration_signature(config: GraphPrioritizationConfig) -> str:
    payload = asdict(config)
    payload.pop("graph_database_path", None)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _clean_value(value: object) -> object:
    """Return JSON-safe graph metadata while enforcing the label boundary."""

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(key): _clean_value(item)
            for key, item in value.items()
            if str(key).casefold() not in FORBIDDEN_LABEL_FIELDS
        }
    if isinstance(value, (tuple, list, set)):
        return [_clean_value(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def _json(value: object) -> str:
    return json.dumps(
        _clean_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _node_times(alert: AlertObject) -> tuple[datetime, datetime]:
    if isinstance(alert, NormalizedAlert):
        return alert.timestamp, alert.timestamp
    return alert.first_seen, alert.last_seen


class SQLiteAlertGraphStore:
    """Store alert nodes, entity nodes, directed roles, members, and scores."""

    def __init__(
        self,
        path: str | Path,
        config: GraphPrioritizationConfig,
    ) -> None:
        self._path = Path(path).expanduser()
        self.config = config
        self.config_signature = _configuration_signature(config)
        self.pattern_extractor = GraphAlertPatternExtractor(
            config.pattern_numeric_min_digits
        )

    @property
    def path(self) -> Path:
        return self._path

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE graph_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE graph_alert_nodes (
                alert_id TEXT PRIMARY KEY,
                object_type TEXT NOT NULL CHECK (object_type IN ('alert', 'meta_alert')),
                alert_source TEXT NOT NULL,
                alert_semantics TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                protocols_json TEXT NOT NULL,
                source_ports_json TEXT NOT NULL,
                destination_ports_json TEXT NOT NULL,
                attribute_template TEXT NOT NULL,
                statistics_json TEXT NOT NULL
            );

            CREATE TABLE graph_entity_nodes (
                entity_id TEXT PRIMARY KEY
            );

            CREATE TABLE graph_alert_entity_edges (
                alert_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('source', 'target')),
                PRIMARY KEY (alert_id, entity_id, role),
                FOREIGN KEY (alert_id) REFERENCES graph_alert_nodes(alert_id),
                FOREIGN KEY (entity_id) REFERENCES graph_entity_nodes(entity_id)
            );

            CREATE TABLE graph_alert_services (
                alert_id TEXT NOT NULL,
                service TEXT NOT NULL,
                PRIMARY KEY (alert_id, service),
                FOREIGN KEY (alert_id) REFERENCES graph_alert_nodes(alert_id)
            );

            CREATE TABLE graph_member_edges (
                meta_alert_id TEXT NOT NULL,
                member_alert_id TEXT NOT NULL,
                PRIMARY KEY (meta_alert_id, member_alert_id),
                FOREIGN KEY (meta_alert_id) REFERENCES graph_alert_nodes(alert_id)
            );

            CREATE TABLE graph_original_alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                alert_source TEXT NOT NULL,
                alert_semantics TEXT NOT NULL,
                source_entity TEXT,
                target_entity TEXT,
                service TEXT,
                raw_reference TEXT
            );

            CREATE TABLE graph_scores (
                alert_id TEXT PRIMARY KEY,
                alert_pattern_score REAL NOT NULL,
                entity_score REAL NOT NULL,
                relation_score REAL NOT NULL,
                total_score REAL NOT NULL,
                rank INTEGER NOT NULL,
                candidate INTEGER NOT NULL CHECK (candidate IN (0, 1)),
                FOREIGN KEY (alert_id) REFERENCES graph_alert_nodes(alert_id)
            );

            CREATE INDEX idx_graph_entity_edges_entity
                ON graph_alert_entity_edges(entity_id, role, alert_id);
            CREATE INDEX idx_graph_alert_nodes_time
                ON graph_alert_nodes(start_time, end_time);
            CREATE INDEX idx_graph_scores_rank
                ON graph_scores(candidate, rank);
            CREATE INDEX idx_graph_member_edges_member
                ON graph_member_edges(member_alert_id);
            """
        )

    @staticmethod
    def _validate(result: GraphPrioritizationResult) -> None:
        state_ids = set(result.graph_state.alerts_by_id)
        ranked_ids = {alert_object_id(item.alert) for item in result.ranked_alerts}
        if state_ids != ranked_ids:
            raise AlertGraphPersistenceError(
                "ranked alerts and graph alert nodes do not contain the same IDs"
            )
        candidate_ids = {alert_object_id(item.alert) for item in result.candidates}
        if not candidate_ids.issubset(ranked_ids):
            raise AlertGraphPersistenceError(
                "module-two candidates must be a subset of ranked alerts"
            )
        if any(not item.forwarded for item in result.candidates):
            raise AlertGraphPersistenceError(
                "module-two candidate is not marked as forwarded"
            )

    def save(self, result: GraphPrioritizationResult) -> GraphPersistenceInfo:
        self._validate(result)
        state = result.graph_state
        saved_at = datetime.now(timezone.utc)

        alert_rows: list[tuple[object, ...]] = []
        entity_rows: set[tuple[str]] = set()
        entity_edge_rows: set[tuple[str, str, str]] = set()
        service_rows: set[tuple[str, str]] = set()
        member_rows: set[tuple[str, str]] = set()
        referenced_original_ids: set[str] = set()
        for identifier in sorted(state.alerts_by_id):
            alert = state.alerts_by_id[identifier]
            start_time, end_time = _node_times(alert)
            pattern = self.pattern_extractor.extract(alert)
            metadata = (
                alert.statistics
                if isinstance(alert, MetaAlert)
                else alert.attributes
            )
            alert_rows.append(
                (
                    identifier,
                    "meta_alert" if isinstance(alert, MetaAlert) else "alert",
                    alert.alert_source,
                    alert.alert_semantics,
                    start_time.isoformat(),
                    end_time.isoformat(),
                    _json(pattern.protocols),
                    _json(alert_ports(alert, role="source")),
                    _json(alert_ports(alert, role="destination")),
                    pattern.attribute_template,
                    _json(metadata),
                )
            )
            sources, targets = alert_object_entities(alert)
            for role, values in (("source", sources), ("target", targets)):
                for entity in sorted(set(values)):
                    entity_rows.add((entity,))
                    entity_edge_rows.add((identifier, entity, role))
            services = (
                alert.services
                if isinstance(alert, MetaAlert)
                else (alert.service,)
                if alert.service
                else ()
            )
            for service in sorted(set(services)):
                service_rows.add((identifier, service))
            if isinstance(alert, MetaAlert):
                for member_id in alert.member_alert_ids:
                    member_rows.add((identifier, member_id))
                    referenced_original_ids.add(member_id)
            else:
                referenced_original_ids.add(identifier)

        original_rows = []
        for identifier in sorted(referenced_original_ids):
            original = state.original_alerts_by_id.get(identifier)
            if original is None:
                continue
            original_rows.append(
                (
                    original.alert_id,
                    original.timestamp.isoformat(),
                    original.alert_source,
                    original.alert_semantics,
                    original.source_entity,
                    original.target_entity,
                    original.service,
                    original.raw_reference,
                )
            )

        score_rows = [
            (
                alert_object_id(item.alert),
                item.score.alert_pattern,
                item.score.entity,
                item.score.relation,
                item.score.total,
                item.rank,
                int(item.forwarded),
            )
            for item in result.ranked_alerts
        ]
        counts = {
            "alert_node_count": len(alert_rows),
            "entity_node_count": len(entity_rows),
            "entity_edge_count": len(entity_edge_rows),
            "member_edge_count": len(member_rows),
            "original_alert_count": len(original_rows),
            "candidate_count": len(result.candidates),
        }
        metadata = {
            "format": DATABASE_FORMAT,
            "version": str(DATABASE_VERSION),
            "saved_at": saved_at.isoformat(),
            "config_signature": self.config_signature,
            **{key: str(value) for key, value in counts.items()},
        }

        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        os.close(descriptor)
        try:
            connection = sqlite3.connect(temporary_name, timeout=30.0)
            try:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA synchronous = FULL")
                with connection:
                    self._create_schema(connection)
                    connection.executemany(
                        "INSERT INTO graph_metadata(key, value) VALUES (?, ?)",
                        tuple(sorted(metadata.items())),
                    )
                    connection.executemany(
                        """
                        INSERT INTO graph_alert_nodes
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        alert_rows,
                    )
                    connection.executemany(
                        "INSERT INTO graph_entity_nodes VALUES (?)",
                        sorted(entity_rows),
                    )
                    connection.executemany(
                        "INSERT INTO graph_alert_entity_edges VALUES (?, ?, ?)",
                        sorted(entity_edge_rows),
                    )
                    connection.executemany(
                        "INSERT INTO graph_alert_services VALUES (?, ?)",
                        sorted(service_rows),
                    )
                    connection.executemany(
                        "INSERT INTO graph_member_edges VALUES (?, ?)",
                        sorted(member_rows),
                    )
                    connection.executemany(
                        """
                        INSERT INTO graph_original_alerts
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        original_rows,
                    )
                    connection.executemany(
                        "INSERT INTO graph_scores VALUES (?, ?, ?, ?, ?, ?, ?)",
                        score_rows,
                    )
                check = connection.execute("PRAGMA integrity_check").fetchone()
                if check is None or check[0] != "ok":
                    raise AlertGraphPersistenceError(
                        "SQLite integrity_check failed for the alert graph"
                    )
            finally:
                connection.close()
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

        return GraphPersistenceInfo(
            path=str(self.path.resolve()),
            saved_at=saved_at,
            **counts,
        )
