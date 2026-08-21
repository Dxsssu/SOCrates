"""Durable, validated snapshots for the hierarchical alert tree and records."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from ...config import BenignFingerprintConfig
from .event_tree import AlertPath, HierarchicalAlertEventTree, LAYER_ORDER
from .fingerprint import FingerprintCanonicalizer
from .generalization import TypedConstraint
from .repository import (
    FingerprintKind,
    FingerprintRecord,
    InMemoryBenignFingerprintRepository,
)


SNAPSHOT_FORMAT = "socrates-hat-snapshot"
SNAPSHOT_VERSION = 2
DATABASE_FORMAT = "socrates-hat-sqlite"
DATABASE_VERSION = 3
HAT_ALGORITHM_VERSION = 2


class HATSnapshotError(RuntimeError):
    """Raised when a configured HAT snapshot cannot be trusted or restored."""


@dataclass(frozen=True, slots=True)
class HATSnapshotInfo:
    """Auditable metadata describing a saved or restored HAT snapshot."""

    path: str
    created_at: datetime
    fingerprint_count: int
    path_count: int
    total_support: int
    config_signature: str
    fingerprint_ids: tuple[str, ...] = ()


class HATStateStore(Protocol):
    """Persistence contract used by the module-one pipeline bootstrap."""

    @property
    def path(self) -> Path:
        """Return the durable snapshot location."""
        ...

    def load(self) -> HATSnapshotInfo | None:
        """Restore state, returning ``None`` when no snapshot exists."""
        ...

    def save(self) -> HATSnapshotInfo:
        """Atomically persist the current tree and repository state."""
        ...


def _configuration_payload(config: BenignFingerprintConfig) -> dict[str, object]:
    payload = asdict(config)
    payload.pop("hat_database_path", None)
    payload.pop("hat_state_path", None)
    return {
        "hat_algorithm_version": HAT_ALGORITHM_VERSION,
        "benign_fingerprint": payload,
        "layers": [layer.value for layer in LAYER_ORDER],
    }


def _configuration_signature(config: BenignFingerprintConfig) -> str:
    encoded = json.dumps(
        _configuration_payload(config),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise HATSnapshotError(f"snapshot {field_name} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HATSnapshotError(
            f"snapshot {field_name} is not a valid ISO timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise HATSnapshotError(f"snapshot {field_name} must include a timezone")
    return parsed


def _path(value: object) -> AlertPath:
    if not isinstance(value, dict):
        raise HATSnapshotError("snapshot fingerprint path must be an object")
    expected = tuple(layer.value for layer in LAYER_ORDER)
    if len(value) != len(expected) or set(value) != set(expected):
        raise HATSnapshotError(
            "snapshot fingerprint path layers do not match the six-level HAT"
        )
    values = tuple(value[name] for name in expected)
    if not all(isinstance(item, str) for item in values):
        raise HATSnapshotError("snapshot fingerprint path values must be strings")
    return AlertPath(*values)


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise HATSnapshotError(f"snapshot {field_name} must be a string list")
    return tuple(value)


def _constraints(value: object) -> tuple[TypedConstraint, ...]:
    if not isinstance(value, list):
        raise HATSnapshotError("snapshot constraints must be a list")
    result: list[TypedConstraint] = []
    for item in value:
        if not isinstance(item, dict):
            raise HATSnapshotError("snapshot constraint must be an object")
        layer = item.get("layer")
        occurrence = item.get("occurrence")
        placeholder = item.get("placeholder")
        shapes = item.get("accepted_shapes")
        if (
            not isinstance(layer, str)
            or not isinstance(occurrence, int)
            or isinstance(occurrence, bool)
            or occurrence < 0
            or not isinstance(placeholder, str)
        ):
            raise HATSnapshotError("snapshot constraint fields are invalid")
        result.append(
            TypedConstraint(
                layer=layer,
                occurrence=occurrence,
                placeholder=placeholder,
                accepted_shapes=_string_tuple(shapes, "accepted_shapes"),
            )
        )
    return tuple(result)


def _constraint_payload(constraint: TypedConstraint) -> dict[str, object]:
    return {
        "layer": constraint.layer,
        "occurrence": constraint.occurrence,
        "placeholder": constraint.placeholder,
        "accepted_shapes": list(constraint.accepted_shapes),
    }


def _exact_records(
    records: tuple[FingerprintRecord, ...] | list[FingerprintRecord],
) -> tuple[FingerprintRecord, ...]:
    return tuple(record for record in records if record.kind is FingerprintKind.EXACT)


class JSONHATSnapshotStore:
    """Persist the HAT and verified records in one atomic JSON snapshot."""

    def __init__(
        self,
        path: str | Path,
        *,
        tree: HierarchicalAlertEventTree,
        repository: InMemoryBenignFingerprintRepository,
        canonicalizer: FingerprintCanonicalizer,
        config: BenignFingerprintConfig,
    ) -> None:
        self._path = Path(path).expanduser()
        self.tree = tree
        self.repository = repository
        self.canonicalizer = canonicalizer
        self.config = config
        self.config_signature = _configuration_signature(config)

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_empty(self) -> None:
        if self.tree.total_support or len(self.repository):
            raise HATSnapshotError(
                "cannot restore a HAT snapshot into non-empty in-memory state"
            )

    def load(self) -> HATSnapshotInfo | None:
        if not self.path.exists():
            return None
        self._ensure_empty()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HATSnapshotError(f"cannot read HAT snapshot: {self.path}") from exc
        if not isinstance(payload, dict):
            raise HATSnapshotError("HAT snapshot root must be an object")
        if payload.get("format") != SNAPSHOT_FORMAT:
            raise HATSnapshotError("unrecognized HAT snapshot format")
        if payload.get("version") != SNAPSHOT_VERSION:
            raise HATSnapshotError(
                "HAT snapshot version is incompatible; rebuild the snapshot"
            )
        snapshot_signature = payload.get("config_signature")
        if snapshot_signature != self.config_signature:
            raise HATSnapshotError(
                "HAT snapshot configuration does not match the current HAT "
                f"configuration: {self.path}"
            )
        records = payload.get("fingerprints")
        if not isinstance(records, list) or not records:
            raise HATSnapshotError("HAT snapshot contains no fingerprint records")

        created_at = _datetime(payload.get("created_at"), "created_at")
        validated_records: list[FingerprintRecord] = []
        restored_ids: list[str] = []
        seen_ids: set[str] = set()
        seen_canonical: set[str] = set()
        for value in records:
            if not isinstance(value, dict):
                raise HATSnapshotError("snapshot fingerprint must be an object")
            path = _path(value.get("path"))
            canonical = value.get("canonical_fingerprint")
            digest = value.get("digest")
            fingerprint_id = value.get("fingerprint_id")
            support = value.get("support")
            verified = value.get("verified")
            kind_raw = value.get("kind")
            active = value.get("active")
            generalization_key = value.get("generalization_key")
            provenance_truncated = value.get("provenance_truncated")
            distinct_exact_paths = value.get("distinct_exact_paths")
            if not isinstance(canonical, str) or not isinstance(digest, str):
                raise HATSnapshotError("snapshot fingerprint values must be strings")
            if not isinstance(fingerprint_id, str) or not fingerprint_id:
                raise HATSnapshotError("snapshot fingerprint_id must be non-empty")
            if fingerprint_id in seen_ids:
                raise HATSnapshotError(
                    f"duplicate snapshot fingerprint_id: {fingerprint_id}"
                )
            if not isinstance(support, int) or isinstance(support, bool) or support < 1:
                raise HATSnapshotError("snapshot fingerprint support must be positive")
            if not isinstance(verified, bool):
                raise HATSnapshotError("snapshot fingerprint verified must be boolean")
            try:
                kind = FingerprintKind(kind_raw)
            except (TypeError, ValueError) as exc:
                raise HATSnapshotError("snapshot fingerprint kind is invalid") from exc
            if not isinstance(active, bool):
                raise HATSnapshotError("snapshot fingerprint active must be boolean")
            if generalization_key is not None and not isinstance(
                generalization_key, str
            ):
                raise HATSnapshotError(
                    "snapshot generalization_key must be a string or null"
                )
            if not isinstance(provenance_truncated, bool):
                raise HATSnapshotError(
                    "snapshot provenance_truncated must be boolean"
                )
            if (
                not isinstance(distinct_exact_paths, int)
                or isinstance(distinct_exact_paths, bool)
                or distinct_exact_paths < 1
            ):
                raise HATSnapshotError(
                    "snapshot distinct_exact_paths must be positive"
                )
            expected_canonical = self.canonicalizer.canonicalize(path)
            expected_digest = self.canonicalizer.digest(expected_canonical)
            if canonical != expected_canonical or digest != expected_digest:
                raise HATSnapshotError(
                    f"snapshot fingerprint integrity check failed: {fingerprint_id}"
                )
            if canonical in seen_canonical:
                raise HATSnapshotError(
                    f"duplicate snapshot canonical fingerprint: {fingerprint_id}"
                )
            expires_raw = value.get("expires_at")
            record = FingerprintRecord(
                fingerprint_id=fingerprint_id,
                digest=digest,
                canonical_fingerprint=canonical,
                path=path,
                support=support,
                verified=verified,
                created_at=_datetime(value.get("created_at"), "created_at"),
                updated_at=_datetime(value.get("updated_at"), "updated_at"),
                expires_at=(
                    _datetime(expires_raw, "expires_at")
                    if expires_raw is not None
                    else None
                ),
                kind=kind,
                active=active,
                generalization_key=generalization_key,
                generalized_fields=_string_tuple(
                    value.get("generalized_fields"),
                    "generalized_fields",
                ),
                constraints=_constraints(value.get("constraints")),
                provenance_alert_ids=_string_tuple(
                    value.get("provenance_alert_ids"),
                    "provenance_alert_ids",
                ),
                provenance_truncated=provenance_truncated,
                distinct_exact_paths=distinct_exact_paths,
            )
            validated_records.append(record)
            restored_ids.append(fingerprint_id)
            seen_ids.add(fingerprint_id)
            seen_canonical.add(canonical)

        tree_summary = payload.get("tree_summary")
        if not isinstance(tree_summary, dict):
            raise HATSnapshotError("snapshot tree_summary must be an object")
        exact_records = _exact_records(validated_records)
        prefixes = {
            path.values[:depth]
            for path in (record.path for record in exact_records)
            for depth in range(1, len(LAYER_ORDER) + 1)
        }
        expected_summary = {
            "node_count": 1 + len(prefixes),
            "path_count": len(exact_records),
            "total_support": sum(record.support for record in exact_records),
        }
        for key, expected in expected_summary.items():
            actual = tree_summary.get(key)
            if (
                not isinstance(actual, int)
                or isinstance(actual, bool)
                or actual != expected
            ):
                raise HATSnapshotError(
                    f"snapshot tree summary mismatch for {key}: expected {expected}"
                )

        # Mutate the live objects only after the complete snapshot has passed
        # validation, so a corrupt file cannot leave a partially restored HAT.
        for record in validated_records:
            if record.kind is FingerprintKind.EXACT:
                self.tree.insert(record.path, count=record.support)
            self.repository.save(record)
        return HATSnapshotInfo(
            path=str(self.path.resolve()),
            created_at=created_at,
            fingerprint_count=len(restored_ids),
            path_count=self.tree.path_count,
            total_support=self.tree.total_support,
            config_signature=self.config_signature,
            fingerprint_ids=tuple(restored_ids),
        )

    def save(self) -> HATSnapshotInfo:
        records = self.repository.records()
        if not records:
            raise HATSnapshotError("refusing to save an empty HAT snapshot")
        exact_records = _exact_records(records)
        paths = self.tree.paths()
        path_support = {path.values: support for path, support in paths}
        if len(paths) != len(exact_records):
            raise HATSnapshotError(
                "HAT path count and fingerprint record count are inconsistent"
            )
        for record in exact_records:
            if path_support.get(record.path.values) != record.support:
                raise HATSnapshotError(
                    f"HAT support differs from repository: {record.fingerprint_id}"
                )
        created_at = datetime.now(timezone.utc)
        payload = {
            "format": SNAPSHOT_FORMAT,
            "version": SNAPSHOT_VERSION,
            "created_at": created_at.isoformat(),
            "config_signature": self.config_signature,
            "configuration": _configuration_payload(self.config),
            "tree_summary": {
                "node_count": self.tree.node_count,
                "path_count": self.tree.path_count,
                "total_support": self.tree.total_support,
            },
            "fingerprints": [
                {
                    "fingerprint_id": record.fingerprint_id,
                    "digest": record.digest,
                    "canonical_fingerprint": record.canonical_fingerprint,
                    "path": record.path.as_dict(),
                    "support": record.support,
                    "verified": record.verified,
                    "created_at": record.created_at.isoformat(),
                    "updated_at": record.updated_at.isoformat(),
                    "expires_at": (
                        record.expires_at.isoformat()
                        if record.expires_at is not None
                        else None
                    ),
                    "kind": record.kind.value,
                    "active": record.active,
                    "generalization_key": record.generalization_key,
                    "generalized_fields": list(record.generalized_fields),
                    "constraints": [
                        _constraint_payload(constraint)
                        for constraint in record.constraints
                    ],
                    "provenance_alert_ids": list(record.provenance_alert_ids),
                    "provenance_truncated": record.provenance_truncated,
                    "distinct_exact_paths": record.distinct_exact_paths,
                }
                for record in records
            ],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
            text=True,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    payload,
                    handle,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        return HATSnapshotInfo(
            path=str(self.path.resolve()),
            created_at=created_at,
            fingerprint_count=len(records),
            path_count=self.tree.path_count,
            total_support=self.tree.total_support,
            config_signature=self.config_signature,
            fingerprint_ids=tuple(record.fingerprint_id for record in records),
        )


class SQLiteHATStateStore:
    """Persist HAT paths and verified fingerprints in a transactional database."""

    _METADATA_TABLE = "hat_metadata"
    _FINGERPRINT_TABLE = "hat_fingerprints"

    def __init__(
        self,
        path: str | Path,
        *,
        tree: HierarchicalAlertEventTree,
        repository: InMemoryBenignFingerprintRepository,
        canonicalizer: FingerprintCanonicalizer,
        config: BenignFingerprintConfig,
    ) -> None:
        self._path = Path(path).expanduser()
        self.tree = tree
        self.repository = repository
        self.canonicalizer = canonicalizer
        self.config = config
        self.config_signature = _configuration_signature(config)

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_empty(self) -> None:
        if self.tree.total_support or len(self.repository):
            raise HATSnapshotError(
                "cannot restore a HAT database into non-empty in-memory state"
            )

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE hat_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE hat_fingerprints (
                fingerprint_id TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                canonical_fingerprint TEXT NOT NULL UNIQUE,
                alert_source TEXT NOT NULL,
                alert_semantics TEXT NOT NULL,
                source_entity TEXT NOT NULL,
                target_entity TEXT NOT NULL,
                service_information TEXT NOT NULL,
                attribute_template TEXT NOT NULL,
                support INTEGER NOT NULL CHECK (support >= 1),
                verified INTEGER NOT NULL CHECK (verified IN (0, 1)),
                expires_at TEXT,
                kind TEXT NOT NULL CHECK (kind IN ('exact', 'generalized')),
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                generalization_key TEXT,
                generalized_fields_json TEXT NOT NULL,
                constraints_json TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                provenance_truncated INTEGER NOT NULL
                    CHECK (provenance_truncated IN (0, 1)),
                distinct_exact_paths INTEGER NOT NULL
                    CHECK (distinct_exact_paths >= 1)
            );

            CREATE INDEX idx_hat_fingerprints_digest
                ON hat_fingerprints(digest);

            CREATE INDEX idx_hat_fingerprints_path_prefix
                ON hat_fingerprints(
                    alert_source,
                    alert_semantics,
                    source_entity,
                    target_entity,
                    service_information
                );

            CREATE INDEX idx_hat_fingerprints_generalization
                ON hat_fingerprints(generalization_key, kind);
            """
        )

    def _validate_record(
        self,
        row: sqlite3.Row,
        restored_at: datetime,
    ) -> FingerprintRecord:
        path = AlertPath(
            alert_source=row["alert_source"],
            alert_semantics=row["alert_semantics"],
            source_entity=row["source_entity"],
            target_entity=row["target_entity"],
            service_information=row["service_information"],
            attribute_template=row["attribute_template"],
        )
        if not all(isinstance(value, str) for value in path.values):
            raise HATSnapshotError("HAT database path values must be strings")
        fingerprint_id = row["fingerprint_id"]
        digest = row["digest"]
        canonical = row["canonical_fingerprint"]
        support = row["support"]
        verified = row["verified"]
        if not isinstance(fingerprint_id, str) or not fingerprint_id:
            raise HATSnapshotError("HAT database fingerprint_id must be non-empty")
        if not isinstance(digest, str) or not isinstance(canonical, str):
            raise HATSnapshotError("HAT database fingerprint values must be strings")
        if not isinstance(support, int) or isinstance(support, bool) or support < 1:
            raise HATSnapshotError("HAT database support must be positive")
        if verified not in (0, 1):
            raise HATSnapshotError("HAT database verified value must be boolean")
        try:
            kind = FingerprintKind(row["kind"])
        except (TypeError, ValueError) as exc:
            raise HATSnapshotError("HAT database fingerprint kind is invalid") from exc
        active = row["active"]
        generalization_key = row["generalization_key"]
        provenance_truncated = row["provenance_truncated"]
        distinct_exact_paths = row["distinct_exact_paths"]
        if active not in (0, 1) or provenance_truncated not in (0, 1):
            raise HATSnapshotError("HAT database boolean value is invalid")
        if generalization_key is not None and not isinstance(generalization_key, str):
            raise HATSnapshotError(
                "HAT database generalization_key must be a string or null"
            )
        if (
            not isinstance(distinct_exact_paths, int)
            or isinstance(distinct_exact_paths, bool)
            or distinct_exact_paths < 1
        ):
            raise HATSnapshotError(
                "HAT database distinct_exact_paths must be positive"
            )
        try:
            generalized_fields = _string_tuple(
                json.loads(row["generalized_fields_json"]),
                "generalized_fields",
            )
            constraints = _constraints(json.loads(row["constraints_json"]))
            provenance = _string_tuple(
                json.loads(row["provenance_json"]),
                "provenance_alert_ids",
            )
        except (json.JSONDecodeError, TypeError) as exc:
            raise HATSnapshotError(
                "HAT database fingerprint JSON metadata is invalid"
            ) from exc
        expected_canonical = self.canonicalizer.canonicalize(path)
        expected_digest = self.canonicalizer.digest(expected_canonical)
        if canonical != expected_canonical or digest != expected_digest:
            raise HATSnapshotError(
                f"HAT database fingerprint integrity check failed: {fingerprint_id}"
            )
        expires_raw = row["expires_at"]
        return FingerprintRecord(
            fingerprint_id=fingerprint_id,
            digest=digest,
            canonical_fingerprint=canonical,
            path=path,
            support=support,
            verified=bool(verified),
            # These remain runtime fields on FingerprintRecord, but are not
            # persisted per row because HAT matching does not use them.
            created_at=restored_at,
            updated_at=restored_at,
            expires_at=(
                _datetime(expires_raw, "expires_at")
                if expires_raw is not None
                else None
            ),
            kind=kind,
            active=bool(active),
            generalization_key=generalization_key,
            generalized_fields=generalized_fields,
            constraints=constraints,
            provenance_alert_ids=provenance,
            provenance_truncated=bool(provenance_truncated),
            distinct_exact_paths=distinct_exact_paths,
        )

    @staticmethod
    def _expected_tree_summary(
        records: tuple[FingerprintRecord, ...],
    ) -> dict[str, int]:
        records = _exact_records(records)
        prefixes = {
            path.values[:depth]
            for path in (record.path for record in records)
            for depth in range(1, len(LAYER_ORDER) + 1)
        }
        return {
            "node_count": 1 + len(prefixes),
            "path_count": len(records),
            "total_support": sum(record.support for record in records),
        }

    @staticmethod
    def _metadata_integer(metadata: dict[str, str], key: str) -> int:
        try:
            value = int(metadata[key])
        except (KeyError, TypeError, ValueError) as exc:
            raise HATSnapshotError(
                f"HAT database metadata {key} must be an integer"
            ) from exc
        return value

    def load(self) -> HATSnapshotInfo | None:
        if not self.path.exists():
            return None
        self._ensure_empty()
        try:
            connection = sqlite3.connect(self.path, timeout=30.0)
            connection.row_factory = sqlite3.Row
            try:
                table_names = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                required_tables = {self._METADATA_TABLE, self._FINGERPRINT_TABLE}
                if not required_tables.issubset(table_names):
                    raise HATSnapshotError(
                        "HAT database schema is missing required tables"
                    )
                metadata = {
                    row["key"]: row["value"]
                    for row in connection.execute("SELECT key, value FROM hat_metadata")
                }
                if metadata.get("format") != DATABASE_FORMAT:
                    raise HATSnapshotError("unrecognized HAT database format")
                if metadata.get("version") != str(DATABASE_VERSION):
                    raise HATSnapshotError(
                        "HAT database version is incompatible; rebuild the database"
                    )
                if metadata.get("config_signature") != self.config_signature:
                    raise HATSnapshotError(
                        "HAT database configuration does not match the current HAT "
                        f"configuration: {self.path}"
                    )
                created_at = _datetime(metadata.get("created_at"), "created_at")
                rows = tuple(
                    connection.execute(
                        """
                        SELECT * FROM hat_fingerprints
                        ORDER BY digest, canonical_fingerprint
                        """
                    )
                )
                if not rows:
                    raise HATSnapshotError(
                        "HAT database contains no fingerprint records"
                    )
                records = tuple(self._validate_record(row, created_at) for row in rows)
                expected_summary = self._expected_tree_summary(records)
                for key, expected in expected_summary.items():
                    actual = self._metadata_integer(metadata, key)
                    if actual != expected:
                        raise HATSnapshotError(
                            f"HAT database tree summary mismatch for {key}: "
                            f"expected {expected}"
                        )
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise HATSnapshotError(f"cannot read HAT database: {self.path}") from exc

        # Restore only after every database row and metadata value is valid.
        for record in records:
            if record.kind is FingerprintKind.EXACT:
                self.tree.insert(record.path, count=record.support)
            self.repository.save(record)
        return HATSnapshotInfo(
            path=str(self.path.resolve()),
            created_at=created_at,
            fingerprint_count=len(records),
            path_count=self.tree.path_count,
            total_support=self.tree.total_support,
            config_signature=self.config_signature,
            fingerprint_ids=tuple(record.fingerprint_id for record in records),
        )

    def save(self) -> HATSnapshotInfo:
        records = self.repository.records()
        if not records:
            raise HATSnapshotError("refusing to save an empty HAT database")
        expected_summary = self._expected_tree_summary(records)
        actual_summary = {
            "node_count": self.tree.node_count,
            "path_count": self.tree.path_count,
            "total_support": self.tree.total_support,
        }
        if expected_summary != actual_summary:
            raise HATSnapshotError(
                "HAT tree and fingerprint repository are inconsistent"
            )
        if self.path.exists():
            raise HATSnapshotError(
                f"refusing to overwrite an existing HAT database: {self.path}"
            )

        created_at = datetime.now(timezone.utc)
        metadata = {
            "format": DATABASE_FORMAT,
            "version": str(DATABASE_VERSION),
            "created_at": created_at.isoformat(),
            "config_signature": self.config_signature,
            "configuration": json.dumps(
                _configuration_payload(self.config),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            **{key: str(value) for key, value in actual_summary.items()},
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
                connection.execute("PRAGMA synchronous = FULL")
                with connection:
                    self._create_schema(connection)
                    connection.executemany(
                        "INSERT INTO hat_metadata(key, value) VALUES (?, ?)",
                        tuple(sorted(metadata.items())),
                    )
                    connection.executemany(
                        """
                        INSERT INTO hat_fingerprints (
                            fingerprint_id,
                            digest,
                            canonical_fingerprint,
                            alert_source,
                            alert_semantics,
                            source_entity,
                            target_entity,
                            service_information,
                            attribute_template,
                            support,
                            verified,
                            expires_at,
                            kind,
                            active,
                            generalization_key,
                            generalized_fields_json,
                            constraints_json,
                            provenance_json,
                            provenance_truncated,
                            distinct_exact_paths
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            (
                                record.fingerprint_id,
                                record.digest,
                                record.canonical_fingerprint,
                                *record.path.values,
                                record.support,
                                int(record.verified),
                                (
                                    record.expires_at.isoformat()
                                    if record.expires_at is not None
                                    else None
                                ),
                                record.kind.value,
                                int(record.active),
                                record.generalization_key,
                                json.dumps(
                                    list(record.generalized_fields),
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                ),
                                json.dumps(
                                    [
                                        _constraint_payload(constraint)
                                        for constraint in record.constraints
                                    ],
                                    ensure_ascii=False,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                json.dumps(
                                    list(record.provenance_alert_ids),
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                ),
                                int(record.provenance_truncated),
                                record.distinct_exact_paths,
                            )
                            for record in records
                        ),
                    )
            finally:
                connection.close()
            os.chmod(temporary_name, 0o600)
            if self.path.exists():
                raise HATSnapshotError(
                    f"HAT database appeared during creation: {self.path}"
                )
            os.replace(temporary_name, self.path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        return HATSnapshotInfo(
            path=str(self.path.resolve()),
            created_at=created_at,
            fingerprint_count=len(records),
            path_count=self.tree.path_count,
            total_support=self.tree.total_support,
            config_signature=self.config_signature,
            fingerprint_ids=tuple(record.fingerprint_id for record in records),
        )
