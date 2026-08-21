"""End-to-end orchestration for the three-stage SOCRates pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .models import (
    FingerprintDecision,
    NormalizedAlert,
    PipelineResult,
    Stage1AggregationResult,
)
from .modules.benign_fingerprint import (
    AlertPreprocessor,
    BenignFingerprintFilter,
    HATSnapshotInfo,
    HATStateStore,
    IdentityAlertPreprocessor,
)
from .modules.graph_prioritization import GraphAlertPrioritizer
from .modules.llm_investigation import (
    EvidenceDrivenInvestigator,
    FalsePositiveKnowledgeBase,
)


@dataclass(slots=True)
class SOCRatesPipeline:
    """Connect the three modules without prescribing their implementations."""

    fingerprint_filter: BenignFingerprintFilter
    graph_prioritizer: GraphAlertPrioritizer
    investigator: EvidenceDrivenInvestigator
    # None passes every module-two candidate into module three.
    max_investigations: int | None = None
    knowledge_base: FalsePositiveKnowledgeBase | None = None
    alert_preprocessor: AlertPreprocessor | None = None
    hat_state_store: HATStateStore | None = None
    bootstrap_aggregation: Stage1AggregationResult | None = field(
        default=None,
        init=False,
    )
    hat_state_status: str = field(default="not_started", init=False)
    hat_snapshot_info: HATSnapshotInfo | None = field(default=None, init=False)
    _bootstrap_fingerprint_ids: tuple[str, ...] = field(default=(), init=False)
    _bootstrap_completed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.max_investigations is not None and self.max_investigations < 1:
            raise ValueError("max_investigations must be at least 1")
        if self.alert_preprocessor is None:
            self.alert_preprocessor = IdentityAlertPreprocessor()

    def bootstrap_benign_memory(
        self,
        alerts: Iterable[NormalizedAlert],
    ) -> tuple[str, ...]:
        """Restore or initialize durable fingerprints and false-positive knowledge."""

        if self._bootstrap_completed:
            return self._bootstrap_fingerprint_ids

        alert_batch = tuple(alerts)
        assert self.alert_preprocessor is not None
        aggregation = self.alert_preprocessor.aggregate(alert_batch)
        self.bootstrap_aggregation = aggregation
        if self.knowledge_base is not None:
            load_prebuilt = getattr(
                self.knowledge_base,
                "load_prebuilt_documents",
                None,
            )
            loaded_prebuilt = bool(load_prebuilt()) if callable(load_prebuilt) else False
            if not loaded_prebuilt:
                self.knowledge_base.build(alert_batch)

        snapshot = (
            self.hat_state_store.load() if self.hat_state_store is not None else None
        )
        if snapshot is not None:
            fingerprint_ids = snapshot.fingerprint_ids
            self.hat_state_status = "loaded"
            self.hat_snapshot_info = snapshot
        else:
            fingerprint_ids = tuple(
                self.fingerprint_filter.add_verified_benign(alert)
                for alert in aggregation.alerts
            )
            if self.hat_state_store is not None:
                snapshot = self.hat_state_store.save()
                fingerprint_ids = snapshot.fingerprint_ids
                self.hat_state_status = "created"
                self.hat_snapshot_info = snapshot
            else:
                self.hat_state_status = "in_memory"

        self._bootstrap_fingerprint_ids = fingerprint_ids
        self._bootstrap_completed = True
        return fingerprint_ids

    def process(self, alerts: Iterable[NormalizedAlert]) -> PipelineResult:
        """Run fingerprint filtering, graph prioritization, and investigation."""

        alert_batch = tuple(alerts)
        assert self.alert_preprocessor is not None
        aggregation = self.alert_preprocessor.aggregate(alert_batch)
        fingerprint_results = tuple(
            self.fingerprint_filter.evaluate(alert) for alert in aggregation.alerts
        )
        forwarded_alerts = tuple(
            alert
            for alert, result in zip(
                aggregation.alerts,
                fingerprint_results,
                strict=True,
            )
            if result.decision is FingerprintDecision.FORWARD
        )

        graph_result = self.graph_prioritizer.prioritize(
            forwarded_alerts,
            original_alerts_by_id=aggregation.original_alerts_by_id,
        )
        if self.max_investigations is None:
            selected_candidates = graph_result.candidates
            deferred_candidates = ()
        else:
            selected_candidates = graph_result.candidates[: self.max_investigations]
            deferred_candidates = graph_result.candidates[self.max_investigations :]
        investigate_many = getattr(self.investigator, "investigate_many", None)
        if callable(investigate_many):
            adjudications = investigate_many(
                selected_candidates,
                graph_result.graph_state,
            )
        else:
            adjudications = tuple(
                self.investigator.investigate(candidate, graph_result.graph_state)
                for candidate in selected_candidates
            )
        return PipelineResult(
            fingerprint_results=fingerprint_results,
            graph_result=graph_result,
            adjudications=adjudications,
            deferred_candidates=deferred_candidates,
            stage1_aggregation=aggregation,
        )
