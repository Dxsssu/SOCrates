"""Verified benign fingerprint repository contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Protocol, runtime_checkable

from .event_tree import AlertPath
from .generalization import TypedConstraint


class FingerprintKind(str, Enum):
    """Exact examples and learned generalized patterns are stored separately."""

    EXACT = "exact"
    GENERALIZED = "generalized"


@dataclass(frozen=True, slots=True)
class FingerprintRecord:
    fingerprint_id: str
    digest: str
    canonical_fingerprint: str
    path: AlertPath
    support: int
    verified: bool
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    kind: FingerprintKind = FingerprintKind.EXACT
    active: bool = True
    generalization_key: str | None = None
    generalized_fields: tuple[str, ...] = ()
    constraints: tuple[TypedConstraint, ...] = ()
    provenance_alert_ids: tuple[str, ...] = ()
    provenance_truncated: bool = False
    distinct_exact_paths: int = 1

    def is_expired(self, at: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        reference = at or datetime.now(timezone.utc)
        if reference.tzinfo is None:
            raise ValueError("Expiration checks require a timezone-aware datetime")
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return reference >= expires_at


@runtime_checkable
class BenignFingerprintRepository(Protocol):
    """Persistence interface for verified benign fingerprints."""

    def get_by_digest(self, digest: str) -> tuple[FingerprintRecord, ...]:
        """Retrieve all records sharing a digest for collision checking."""
        ...

    def save(self, record: FingerprintRecord) -> None:
        """Create or update an analyst-verified fingerprint record."""
        ...

    def records_by_branch(
        self,
        alert_source: str,
        alert_semantics: str,
    ) -> tuple[FingerprintRecord, ...]:
        """Return records in one coarse HAT branch."""
        ...


class InMemoryBenignFingerprintRepository:
    """Thread-safe repository suitable for tests and local execution."""

    def __init__(self) -> None:
        self._records: dict[str, dict[str, FingerprintRecord]] = {}
        self._record_locations: dict[str, tuple[str, str]] = {}
        self._generalization_index: dict[str, set[str]] = {}
        self._branch_index: dict[
            tuple[str, str, FingerprintKind],
            set[str],
        ] = {}
        self._lock = RLock()

    def get_by_digest(self, digest: str) -> tuple[FingerprintRecord, ...]:
        with self._lock:
            bucket = self._records.get(digest, {})
            return tuple(bucket[key] for key in sorted(bucket))

    def get_exact(
        self,
        digest: str,
        canonical_fingerprint: str,
    ) -> FingerprintRecord | None:
        with self._lock:
            return self._records.get(digest, {}).get(canonical_fingerprint)

    def save(self, record: FingerprintRecord) -> None:
        if record.support < 1:
            raise ValueError("Fingerprint support must be at least 1")
        if record.distinct_exact_paths < 1:
            raise ValueError("distinct_exact_paths must be at least 1")
        with self._lock:
            previous = self._record_locations.get(record.fingerprint_id)
            previous_record = (
                self._records.get(previous[0], {}).get(previous[1])
                if previous is not None
                else None
            )
            location = (record.digest, record.canonical_fingerprint)
            if previous is not None and previous != location:
                previous_bucket = self._records.get(previous[0], {})
                previous_bucket.pop(previous[1], None)
                if not previous_bucket:
                    self._records.pop(previous[0], None)
            bucket = self._records.setdefault(record.digest, {})
            collision = bucket.get(record.canonical_fingerprint)
            if collision is not None and collision.fingerprint_id != record.fingerprint_id:
                raise ValueError(
                    "canonical fingerprint is already owned by another record"
                )
            bucket[record.canonical_fingerprint] = record
            self._record_locations[record.fingerprint_id] = location
            if (
                previous_record is not None
                and previous_record.kind is FingerprintKind.EXACT
                and previous_record.generalization_key is not None
                and (
                    record.kind is not FingerprintKind.EXACT
                    or previous_record.generalization_key
                    != record.generalization_key
                )
            ):
                indexed = self._generalization_index.get(
                    previous_record.generalization_key,
                    set(),
                )
                indexed.discard(record.fingerprint_id)
                if not indexed:
                    self._generalization_index.pop(
                        previous_record.generalization_key,
                        None,
                    )
            if previous_record is not None:
                previous_branch = (
                    previous_record.path.alert_source,
                    previous_record.path.alert_semantics,
                    previous_record.kind,
                )
                if previous_branch != (
                    record.path.alert_source,
                    record.path.alert_semantics,
                    record.kind,
                ):
                    indexed_branch = self._branch_index.get(previous_branch, set())
                    indexed_branch.discard(record.fingerprint_id)
                    if not indexed_branch:
                        self._branch_index.pop(previous_branch, None)
            if (
                record.kind is FingerprintKind.EXACT
                and record.generalization_key is not None
            ):
                self._generalization_index.setdefault(
                    record.generalization_key,
                    set(),
                ).add(record.fingerprint_id)
            branch = (
                record.path.alert_source,
                record.path.alert_semantics,
                record.kind,
            )
            self._branch_index.setdefault(branch, set()).add(record.fingerprint_id)

    def get_by_id(self, fingerprint_id: str) -> FingerprintRecord | None:
        with self._lock:
            location = self._record_locations.get(fingerprint_id)
            if location is None:
                return None
            return self._records[location[0]][location[1]]

    def records_by_branch(
        self,
        alert_source: str,
        alert_semantics: str,
    ) -> tuple[FingerprintRecord, ...]:
        with self._lock:
            return tuple(
                record
                for kind in FingerprintKind
                for fingerprint_id in sorted(
                    self._branch_index.get((alert_source, alert_semantics, kind), ())
                )
                if (record := self.get_by_id(fingerprint_id)) is not None
            )

    def generalized_records_by_branch(
        self,
        alert_source: str,
        alert_semantics: str,
    ) -> tuple[FingerprintRecord, ...]:
        with self._lock:
            return tuple(
                record
                for fingerprint_id in sorted(
                    self._branch_index.get(
                        (alert_source, alert_semantics, FingerprintKind.GENERALIZED),
                        (),
                    )
                )
                if (record := self.get_by_id(fingerprint_id)) is not None
            )

    def exact_records_for_generalization(
        self,
        generalization_key: str,
    ) -> tuple[FingerprintRecord, ...]:
        with self._lock:
            return tuple(
                self.get_by_id(fingerprint_id)
                for fingerprint_id in sorted(
                    self._generalization_index.get(generalization_key, ())
                )
            )

    def __len__(self) -> int:
        with self._lock:
            return sum(len(bucket) for bucket in self._records.values())

    def records(self) -> tuple[FingerprintRecord, ...]:
        """Return all records in deterministic digest/canonical order."""

        with self._lock:
            return tuple(
                self._records[digest][canonical]
                for digest in sorted(self._records)
                for canonical in sorted(self._records[digest])
            )

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._record_locations.clear()
            self._generalization_index.clear()
            self._branch_index.clear()
