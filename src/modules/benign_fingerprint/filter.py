"""Exact-first filtering with branch-specific learned benign generalization."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Protocol, runtime_checkable

from ...config import BenignFingerprintConfig
from ...models import (
    AlertObject,
    FingerprintDecision,
    FingerprintResult,
    MetaAlert,
    alert_object_id,
)
from .attribute_template import PayloadAttributeTemplateExtractor
from .event_tree import AlertEventTree, AlertPath, HierarchicalAlertEventTree
from .fingerprint import FingerprintCanonicalizer
from .generalization import (
    infer_generalized_path,
    matches_generalized_path,
    pattern_specificity,
)
from .repository import (
    BenignFingerprintRepository,
    FingerprintKind,
    FingerprintRecord,
)


@runtime_checkable
class BenignFingerprintFilter(Protocol):
    """Contract for module-one benign-memory implementations."""

    def add_verified_benign(self, alert: AlertObject) -> FingerprintRecord:
        """Learn one analyst-verified benign alert object."""
        ...

    def evaluate(self, alert: AlertObject) -> FingerprintResult:
        """Route one alert using exact-to-general benign matching."""
        ...

    def add_verified_batch(
        self,
        alerts: Iterable[AlertObject],
    ) -> tuple[FingerprintRecord, ...]:
        """Learn a batch of analyst-verified benign alert objects."""
        ...


class HierarchicalBenignFingerprintFilter:
    """Filter exact fingerprints first, then uniquely matching learned patterns.

    The public ``tree`` stores only concrete, verified examples.  A second tree
    is used solely to assign examples to a candidate generalization branch;
    generalized records are inferred from multiple distinct exact paths and
    kept separately in the repository for audit and fail-closed matching.
    """

    def __init__(
        self,
        *,
        tree: AlertEventTree,
        canonicalizer: FingerprintCanonicalizer,
        repository: BenignFingerprintRepository,
        config: BenignFingerprintConfig | None = None,
    ) -> None:
        self.tree = tree
        self.canonicalizer = canonicalizer
        self.repository = repository
        self.config = config or BenignFingerprintConfig()
        self._generalization_tree = HierarchicalAlertEventTree(
            template_extractor=PayloadAttributeTemplateExtractor(
                numeric_min_digits=self.config.attribute_numeric_min_digits,
                generalize_dynamic_values=True,
            ),
            entity_ipv4_prefix_length=self.config.entity_ipv4_prefix_length,
            entity_ipv6_prefix_length=self.config.entity_ipv6_prefix_length,
        )

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _expiry(self, now: datetime) -> datetime | None:
        ttl = self.config.fingerprint_ttl_seconds
        return now + timedelta(seconds=ttl) if ttl is not None else None

    def _bounded_provenance(
        self,
        alert_ids: tuple[str, ...],
    ) -> tuple[tuple[str, ...], bool]:
        unique = tuple(dict.fromkeys(alert_ids))
        maximum = self.config.max_provenance_alert_ids
        if maximum is None or len(unique) <= maximum:
            return unique, False
        return unique[-maximum:], True

    def _record_for(
        self,
        path: AlertPath,
        kind: FingerprintKind,
    ) -> FingerprintRecord | None:
        canonical = self.canonicalizer.canonicalize(path)
        digest = self.canonicalizer.digest(canonical)
        get_exact = getattr(self.repository, "get_exact", None)
        record = get_exact(digest, canonical) if get_exact is not None else None
        if record is None:
            record = next(
                (
                    candidate
                    for candidate in self.repository.get_by_digest(digest)
                    if candidate.canonical_fingerprint == canonical
                    and candidate.kind is kind
                ),
                None,
            )
        return record if record is not None and record.kind is kind else None

    def _generalization_key(
        self,
        alert: AlertObject,
        exact_path: AlertPath,
    ) -> tuple[str, AlertPath]:
        candidate = self._generalization_tree.path_for(alert)
        # Source and semantics define the local HAT branch.  Dynamic learning
        # happens beneath it, preventing cross-detector/rule over-generalizing.
        candidate = AlertPath(
            exact_path.alert_source,
            exact_path.alert_semantics,
            candidate.source_entity,
            candidate.target_entity,
            candidate.service_information,
            candidate.attribute_template,
        )
        canonical = self.canonicalizer.canonicalize(candidate)
        return self.canonicalizer.digest(canonical), candidate

    def _exact_records(self, generalization_key: str) -> tuple[FingerprintRecord, ...]:
        lookup = getattr(self.repository, "exact_records_for_generalization", None)
        if lookup is not None:
            return lookup(generalization_key)
        records = getattr(self.repository, "records", lambda: ())()
        return tuple(
            record
            for record in records
            if record.kind is FingerprintKind.EXACT
            and record.generalization_key == generalization_key
        )

    def _record_by_id(self, fingerprint_id: str) -> FingerprintRecord | None:
        lookup = getattr(self.repository, "get_by_id", None)
        if lookup is None:
            return None
        return lookup(fingerprint_id)

    @staticmethod
    def _generalized_id(generalization_key: str) -> str:
        return str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"socrates:generalized:{generalization_key}")
        )

    def _upsert_generalized(
        self,
        generalization_key: str,
        candidate: AlertPath,
        new_exact_record: FingerprintRecord,
        now: datetime,
    ) -> None:
        fingerprint_id = self._generalized_id(generalization_key)
        previous = self._record_by_id(fingerprint_id)
        if previous is not None and matches_generalized_path(
            previous.path,
            new_exact_record.path,
            previous.constraints,
        ):
            provenance, truncated = self._bounded_provenance(
                (*previous.provenance_alert_ids, *new_exact_record.provenance_alert_ids)
            )
            support = previous.support + new_exact_record.support
            distinct_count = previous.distinct_exact_paths + 1
            self.repository.save(
                replace(
                    previous,
                    support=support,
                    verified=previous.verified and new_exact_record.verified,
                    active=(
                        support >= self.config.generalized_minimum_support
                        and distinct_count
                        >= self.config.generalized_minimum_distinct_paths
                    ),
                    updated_at=now,
                    expires_at=self._expiry(now),
                    provenance_alert_ids=provenance,
                    provenance_truncated=(
                        previous.provenance_truncated
                        or new_exact_record.provenance_truncated
                        or truncated
                    ),
                    distinct_exact_paths=distinct_count,
                )
            )
            return

        self._rebuild_generalized(generalization_key, candidate, now)

    def _rebuild_generalized(
        self,
        generalization_key: str,
        candidate: AlertPath,
        now: datetime,
    ) -> None:
        """Recompute one generalized branch from its complete exact evidence."""

        fingerprint_id = self._generalized_id(generalization_key)
        previous = self._record_by_id(fingerprint_id)
        exact_records = self._exact_records(generalization_key)
        distinct_paths = tuple(dict.fromkeys(record.path for record in exact_records))
        inference = infer_generalized_path(candidate, distinct_paths)
        if inference is None:
            if previous is not None and previous.active:
                self.repository.save(replace(previous, active=False, updated_at=now))
            return

        provenance, truncated = self._bounded_provenance(
            tuple(
                alert_id
                for record in exact_records
                for alert_id in record.provenance_alert_ids
            )
        )
        support = sum(record.support for record in exact_records)
        distinct_count = len(distinct_paths)
        active = (
            support >= self.config.generalized_minimum_support
            and distinct_count >= self.config.generalized_minimum_distinct_paths
        )
        canonical = self.canonicalizer.canonicalize(inference.path)
        self.repository.save(
            FingerprintRecord(
                fingerprint_id=fingerprint_id,
                digest=self.canonicalizer.digest(canonical),
                canonical_fingerprint=canonical,
                path=inference.path,
                support=support,
                verified=all(record.verified for record in exact_records),
                created_at=previous.created_at if previous is not None else now,
                updated_at=now,
                expires_at=self._expiry(now),
                kind=FingerprintKind.GENERALIZED,
                active=active,
                generalization_key=generalization_key,
                generalized_fields=inference.generalized_fields,
                constraints=inference.constraints,
                provenance_alert_ids=provenance,
                provenance_truncated=(
                    truncated
                    or any(record.provenance_truncated for record in exact_records)
                ),
                distinct_exact_paths=distinct_count,
            )
        )

    def add_verified_benign(self, alert: AlertObject) -> FingerprintRecord:
        """Store the exact example and cautiously refresh its local pattern."""

        exact_path = self.tree.path_for(alert)
        generalization_key, candidate = self._generalization_key(alert, exact_path)
        canonical = self.canonicalizer.canonicalize(exact_path)
        digest = self.canonicalizer.digest(canonical)
        previous = self._record_for(exact_path, FingerprintKind.EXACT)
        now = self._now()
        provenance, truncated = self._bounded_provenance(
            (
                *(previous.provenance_alert_ids if previous is not None else ()),
                alert_object_id(alert),
            )
        )
        record = FingerprintRecord(
            fingerprint_id=(
                previous.fingerprint_id
                if previous is not None
                else str(uuid.uuid5(uuid.NAMESPACE_URL, f"socrates:exact:{canonical}"))
            ),
            digest=digest,
            canonical_fingerprint=canonical,
            path=exact_path,
            support=(previous.support + 1 if previous is not None else 1),
            verified=True,
            created_at=previous.created_at if previous is not None else now,
            updated_at=now,
            expires_at=self._expiry(now),
            kind=FingerprintKind.EXACT,
            active=True,
            generalization_key=generalization_key,
            provenance_alert_ids=provenance,
            provenance_truncated=(
                truncated or (previous.provenance_truncated if previous else False)
            ),
            distinct_exact_paths=1,
        )
        self.tree.insert(exact_path)
        self.repository.save(record)
        if previous is not None:
            generalized = self._record_by_id(
                self._generalized_id(generalization_key)
            )
            if generalized is not None:
                generalized_provenance, generalized_truncated = (
                    self._bounded_provenance(
                        (*generalized.provenance_alert_ids, alert_object_id(alert))
                    )
                )
                updated_support = generalized.support + 1
                self.repository.save(
                    replace(
                        generalized,
                        support=updated_support,
                        active=(
                            updated_support
                            >= self.config.generalized_minimum_support
                            and generalized.distinct_exact_paths
                            >= self.config.generalized_minimum_distinct_paths
                        ),
                        updated_at=now,
                        expires_at=self._expiry(now),
                        provenance_alert_ids=generalized_provenance,
                        provenance_truncated=(
                            generalized.provenance_truncated
                            or generalized_truncated
                        ),
                    )
                )
            return record
        self._upsert_generalized(generalization_key, candidate, record, now)
        return record

    def add_verified_batch(
        self,
        alerts: Iterable[AlertObject],
    ) -> tuple[FingerprintRecord, ...]:
        """Learn verified examples in arrival order and return exact records."""

        return tuple(self.add_verified_benign(alert) for alert in alerts)

    def add_verified_compacted_batch(
        self,
        alerts: Iterable[AlertObject],
        *,
        progress: Callable[[str, int, int], None] | None = None,
    ) -> tuple[FingerprintRecord, ...]:
        """Learn a large batch without per-alert generalized recomputation.

        Repeated alerts are first compacted by exact six-level path.  Exact
        support is then updated once per path and every affected generalized
        branch is rebuilt once.  The resulting tree/repository state is
        equivalent to batch learning while avoiding quadratic behavior on
        large, repetitive benign corpora.

        ``progress``, when supplied, receives ``(phase, completed, total)`` for
        ``grouping``, ``exact_paths``, and ``generalized_branches``.
        """

        batch = tuple(alerts)
        # [count, provenance_ids, provenance_truncated, key, candidate]
        grouped: dict[AlertPath, list[object]] = {}
        maximum_provenance = self.config.max_provenance_alert_ids
        for index, alert in enumerate(batch, start=1):
            exact_path = self.tree.path_for(alert)
            group = grouped.get(exact_path)
            if group is None:
                generalization_key, candidate = self._generalization_key(
                    alert,
                    exact_path,
                )
                group = [0, [], False, generalization_key, candidate]
                grouped[exact_path] = group
            group[0] = int(group[0]) + 1
            provenance = group[1]
            assert isinstance(provenance, list)
            provenance.append(alert_object_id(alert))
            if (
                maximum_provenance is not None
                and len(provenance) > maximum_provenance
            ):
                del provenance[: len(provenance) - maximum_provenance]
                group[2] = True
            if progress is not None and (index % 1000 == 0 or index == len(batch)):
                progress("grouping", index, len(batch))

        now = self._now()
        exact_records: list[FingerprintRecord] = []
        affected: dict[str, AlertPath] = {}
        group_items = tuple(grouped.items())
        for index, (exact_path, group) in enumerate(group_items, start=1):
            count = int(group[0])
            provenance_ids = tuple(str(value) for value in group[1])
            input_truncated = bool(group[2])
            generalization_key = str(group[3])
            candidate = group[4]
            assert isinstance(candidate, AlertPath)
            canonical = self.canonicalizer.canonicalize(exact_path)
            digest = self.canonicalizer.digest(canonical)
            previous = self._record_for(exact_path, FingerprintKind.EXACT)
            provenance, bounded_truncated = self._bounded_provenance(
                (
                    *(previous.provenance_alert_ids if previous is not None else ()),
                    *provenance_ids,
                )
            )
            record = FingerprintRecord(
                fingerprint_id=(
                    previous.fingerprint_id
                    if previous is not None
                    else str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            f"socrates:exact:{canonical}",
                        )
                    )
                ),
                digest=digest,
                canonical_fingerprint=canonical,
                path=exact_path,
                support=(previous.support if previous is not None else 0) + count,
                verified=True,
                created_at=previous.created_at if previous is not None else now,
                updated_at=now,
                expires_at=self._expiry(now),
                kind=FingerprintKind.EXACT,
                active=True,
                generalization_key=generalization_key,
                provenance_alert_ids=provenance,
                provenance_truncated=(
                    input_truncated
                    or bounded_truncated
                    or (previous.provenance_truncated if previous else False)
                ),
                distinct_exact_paths=1,
            )
            self.tree.insert(exact_path, count=count)
            self.repository.save(record)
            exact_records.append(record)
            affected[generalization_key] = candidate
            if progress is not None and (
                index % 1000 == 0 or index == len(group_items)
            ):
                progress("exact_paths", index, len(group_items))

        affected_items = tuple(sorted(affected.items()))
        for index, (generalization_key, candidate) in enumerate(
            affected_items,
            start=1,
        ):
            self._rebuild_generalized(generalization_key, candidate, now)
            if progress is not None and (
                index % 100 == 0 or index == len(affected_items)
            ):
                progress(
                    "generalized_branches",
                    index,
                    len(affected_items),
                )
        return tuple(exact_records)

    def _rejection_reason(
        self,
        record: FingerprintRecord,
        now: datetime,
    ) -> str | None:
        if not record.active:
            return "inactive_fingerprint"
        if self.config.require_verified_status and not record.verified:
            return "unverified_fingerprint"
        if record.is_expired(now):
            return "expired_fingerprint"
        return None

    def _branch_records(
        self,
        path: AlertPath,
    ) -> tuple[FingerprintRecord, ...]:
        generalized_lookup = getattr(
            self.repository,
            "generalized_records_by_branch",
            None,
        )
        if generalized_lookup is not None:
            return generalized_lookup(path.alert_source, path.alert_semantics)
        lookup = getattr(self.repository, "records_by_branch", None)
        if lookup is None:
            records = getattr(self.repository, "records", lambda: ())()
            return tuple(
                record
                for record in records
                if record.path.alert_source == path.alert_source
                and record.path.alert_semantics == path.alert_semantics
            )
        return lookup(path.alert_source, path.alert_semantics)

    def _generalized_matches(
        self,
        path: AlertPath,
        now: datetime,
    ) -> tuple[FingerprintRecord, ...]:
        return tuple(
            record
            for record in self._branch_records(path)
            if record.kind is FingerprintKind.GENERALIZED
            and record.support >= self.config.generalized_minimum_support
            and record.distinct_exact_paths
            >= self.config.generalized_minimum_distinct_paths
            and self._rejection_reason(record, now) is None
            and matches_generalized_path(record.path, path, record.constraints)
        )

    def evaluate(self, alert: AlertObject) -> FingerprintResult:
        """Apply protected-behavior, exact, then unique generalized matching."""

        alert_id = alert_object_id(alert)
        if isinstance(alert, MetaAlert):
            category = str(alert.statistics.get("behavior_category") or "")
            if category in self.config.high_frequency_always_forward_categories:
                return FingerprintResult(
                    alert_id=alert_id,
                    decision=FingerprintDecision.FORWARD,
                    reason=f"protected_high_frequency_behavior:{category}",
                )

        path = self.tree.path_for(alert)
        match = self.tree.match(path)
        exact_record = self._record_for(path, FingerprintKind.EXACT)
        now = self._now()
        fallback_reason = (
            "insufficient_support"
            if match.matched and match.terminal_support < self.config.minimum_support
            else (
                f"hat_path_not_found:{match.missing_layer.value}"
                if not match.matched and match.missing_layer is not None
                else "fingerprint_record_not_found"
            )
        )
        if match.matched and exact_record is not None:
            rejection = self._rejection_reason(exact_record, now)
            if rejection is not None:
                return FingerprintResult(
                    alert_id=alert_id,
                    decision=FingerprintDecision.FORWARD,
                    fingerprint_id=exact_record.fingerprint_id,
                    support=exact_record.support,
                    reason=rejection,
                )
            if match.terminal_support >= self.config.minimum_support:
                return FingerprintResult(
                    alert_id=alert_id,
                    decision=FingerprintDecision.FILTER,
                    fingerprint_id=exact_record.fingerprint_id,
                    support=match.terminal_support,
                    reason="verified_benign_exact_match",
                )

        candidates = self._generalized_matches(path, now)
        if candidates:
            best_score = max(pattern_specificity(record.path) for record in candidates)
            best = tuple(
                record
                for record in candidates
                if pattern_specificity(record.path) == best_score
            )
            if len(best) == 1:
                record = best[0]
                return FingerprintResult(
                    alert_id=alert_id,
                    decision=FingerprintDecision.FILTER,
                    fingerprint_id=record.fingerprint_id,
                    support=record.support,
                    reason="verified_benign_generalized_match",
                )
            return FingerprintResult(
                alert_id=alert_id,
                decision=FingerprintDecision.FORWARD,
                reason="ambiguous_generalized_match",
            )

        return FingerprintResult(
            alert_id=alert_id,
            decision=FingerprintDecision.FORWARD,
            fingerprint_id=(
                exact_record.fingerprint_id if exact_record is not None else None
            ),
            support=match.terminal_support,
            reason=fallback_reason,
        )
