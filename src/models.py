"""Shared, detector-independent data contracts for SOCRates."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class NormalizedAlert:
    """Canonical alert representation consumed by all three modules."""

    alert_id: str
    timestamp: datetime
    alert_source: str
    alert_semantics: str
    source_entity: str | None = None
    target_entity: str | None = None
    service: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    raw_reference: str | None = None


@dataclass(frozen=True, slots=True)
class MetaAlert:
    """A burst-aware aggregate that retains references to its members."""

    meta_alert_id: str
    member_alert_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    alert_source: str
    alert_semantics: str
    source_entities: tuple[str, ...] = ()
    target_entities: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    statistics: Mapping[str, Any] = field(default_factory=dict)


AlertObject = NormalizedAlert | MetaAlert


def alert_object_id(alert: AlertObject) -> str:
    """Return the stable identifier shared by alerts and meta-alerts."""

    if isinstance(alert, NormalizedAlert):
        return alert.alert_id
    return alert.meta_alert_id


def alert_object_time(alert: AlertObject) -> datetime:
    """Return the event/start time used for ranking and context retrieval."""

    if isinstance(alert, NormalizedAlert):
        return alert.timestamp
    return alert.first_seen


def alert_object_entities(
    alert: AlertObject,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return source and target entities without null placeholders."""

    if isinstance(alert, NormalizedAlert):
        sources = (alert.source_entity,) if alert.source_entity else ()
        targets = (alert.target_entity,) if alert.target_entity else ()
        return sources, targets
    return alert.source_entities, alert.target_entities


@dataclass(frozen=True, slots=True)
class Stage1AggregationResult:
    """Label-free module-one preprocessing output with member traceability."""

    alerts: tuple[AlertObject, ...]
    original_alerts_by_id: Mapping[str, NormalizedAlert]
    member_to_aggregate: Mapping[str, str]

    @property
    def meta_alerts(self) -> tuple[MetaAlert, ...]:
        return tuple(alert for alert in self.alerts if isinstance(alert, MetaAlert))

    @property
    def aggregated_member_count(self) -> int:
        return sum(len(alert.member_alert_ids) for alert in self.meta_alerts)


@dataclass(frozen=True, slots=True)
class AlertGraphState:
    """Typed, auditable in-memory representation of an alert/entity graph."""

    alerts_by_id: Mapping[str, AlertObject]
    original_alerts_by_id: Mapping[str, NormalizedAlert]
    source_entities: Mapping[str, tuple[str, ...]]
    target_entities: Mapping[str, tuple[str, ...]]
    entity_to_alert_ids: Mapping[str, tuple[str, ...]]
    member_to_aggregate: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class AITADSRecord:
    """Normalized AIT-ADS alert plus evaluation-only label sidecar."""

    alert: NormalizedAlert
    label: str | None
    source_file: str
    source_line: int
    detector_source: str


@dataclass(frozen=True, slots=True)
class TianyanRecord:
    """Normalized Tianyan alert plus an evaluation-only truth sidecar."""

    alert: NormalizedAlert
    is_attack: bool
    source_file: str
    source_line: int
    detector_source: str


class FingerprintDecision(str, Enum):
    """Routing outcome produced by the benign fingerprint module."""

    FILTER = "filter"
    FORWARD = "forward"


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    """Auditable result of matching one alert against benign memory."""

    alert_id: str
    decision: FingerprintDecision
    fingerprint_id: str | None = None
    support: int = 0
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AnomalyScore:
    """Component and final scores assigned by the graph module."""

    alert_pattern: float
    entity: float
    relation: float
    total: float


@dataclass(frozen=True, slots=True)
class PrioritizedAlert:
    """An alert or meta-alert ranked for downstream investigation."""

    alert: AlertObject
    score: AnomalyScore
    rank: int
    forwarded: bool
    explanation: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GraphPersistenceInfo:
    """Auditable counts for one durable module-two graph snapshot."""

    path: str
    saved_at: datetime
    alert_node_count: int
    entity_node_count: int
    entity_edge_count: int
    member_edge_count: int
    original_alert_count: int
    candidate_count: int


@dataclass(frozen=True, slots=True)
class GraphPrioritizationResult:
    """Output of graph construction, aggregation, and prioritization."""

    graph_state: AlertGraphState
    ranked_alerts: tuple[PrioritizedAlert, ...]
    candidates: tuple[PrioritizedAlert, ...]
    persistence: GraphPersistenceInfo | None = None


@dataclass(frozen=True, slots=True)
class KnowledgePattern:
    """Retrieved environment-specific false-positive knowledge."""

    pattern_id: str
    index_text: str
    pattern_text: str
    similarity: float | None = None
    provenance: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """A directly referencable item extracted from the alert graph."""

    evidence_id: str
    temporal_role: str
    timestamp: datetime
    alert_semantics: str
    entities: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InvestigationContext:
    """Evidence bundle supplied to the final adjudication component."""

    current_alert: AlertObject
    backward_evidence: tuple[EvidenceItem, ...] = ()
    forward_evidence: tuple[EvidenceItem, ...] = ()
    benign_knowledge: tuple[KnowledgePattern, ...] = ()


class AdjudicationLabel(str, Enum):
    """Final labels currently defined by the paper."""

    TRUE_ALERT = "true_alert"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True, slots=True)
class AdjudicationResult:
    """Structured and evidence-linked LLM adjudication result."""

    alert_id: str
    label: AdjudicationLabel
    rationale: str
    supporting_evidence_ids: tuple[str, ...] = ()
    conflicting_evidence_ids: tuple[str, ...] = ()
    supporting_knowledge_ids: tuple[str, ...] = ()
    rejected_knowledge_ids: tuple[str, ...] = ()
    confidence: float | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Complete output of one SOCRates pipeline run."""

    fingerprint_results: tuple[FingerprintResult, ...]
    graph_result: GraphPrioritizationResult
    adjudications: tuple[AdjudicationResult, ...]
    deferred_candidates: tuple[PrioritizedAlert, ...] = ()
    stage1_aggregation: Stage1AggregationResult | None = None
