"""Public interface of graph aggregation and prioritization."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Mapping, Protocol

from ...config import GraphPrioritizationConfig
from ...models import (
    GraphPrioritizationResult,
    AlertObject,
    NormalizedAlert,
    PrioritizedAlert,
    alert_object_id,
)
from .aggregation import BurstAlertAggregator, IdentityBurstAlertAggregator
from .graph import AlertGraphBuilder, InMemoryAlertGraphBuilder
from .persistence import AlertGraphStore
from .scoring import (
    FrequencyGraphAnomalyScorer,
    GraphAnomalyScorer,
    frequency_window_start,
)


class GraphAlertPrioritizer(Protocol):
    """Graph, score, rank, and route unmatched alerts and stage-1 metas."""

    def prioritize(
        self,
        alerts: Iterable[AlertObject],
        original_alerts_by_id: Mapping[str, NormalizedAlert] | None = None,
    ) -> GraphPrioritizationResult:
        """Return all ranked alerts and candidates for LLM investigation."""
        ...


class DefaultGraphAlertPrioritizer:
    """Compose graph construction, input preparation, scoring, and routing."""

    def __init__(
        self,
        config: GraphPrioritizationConfig | None = None,
        graph_builder: AlertGraphBuilder | None = None,
        aggregator: BurstAlertAggregator | None = None,
        scorer: GraphAnomalyScorer | None = None,
        graph_store: AlertGraphStore | None = None,
    ) -> None:
        self.config = config or GraphPrioritizationConfig()
        self.graph_builder = graph_builder or InMemoryAlertGraphBuilder()
        self.aggregator = aggregator or IdentityBurstAlertAggregator()
        self.scorer = scorer or FrequencyGraphAnomalyScorer(self.config)
        self.graph_store = graph_store

    def prioritize(
        self,
        alerts: Iterable[AlertObject],
        original_alerts_by_id: Mapping[str, NormalizedAlert] | None = None,
    ) -> GraphPrioritizationResult:
        alert_batch = tuple(alerts)
        initial_graph = self.graph_builder.build(
            alert_batch,
            original_alerts_by_id=original_alerts_by_id,
        )
        aggregated = self.aggregator.aggregate(alert_batch)
        graph_state = self.graph_builder.replace_alerts(initial_graph, aggregated)
        scores = self.scorer.score(aggregated, graph_state)
        window_starts = {
            alert_object_id(alert): frequency_window_start(
                alert,
                self.config.frequency_window_seconds,
            )
            for alert in aggregated
        }
        ordered = sorted(
            aggregated,
            key=lambda alert: (
                -scores[alert_object_id(alert)].total,
                alert_object_id(alert),
            ),
        )
        ranked = tuple(
            PrioritizedAlert(
                alert=alert,
                score=scores[alert_object_id(alert)],
                rank=index,
                forwarded=(
                    scores[alert_object_id(alert)].total
                    >= self.config.candidate_threshold
                ),
                explanation={
                    "candidate_threshold": self.config.candidate_threshold,
                    "score_components": ("alert_pattern", "entity", "relation"),
                    "alert_pattern_fields": (
                        "alert_semantics",
                        "protocol",
                        "service",
                        "attribute_template",
                    ),
                    "frequency_window_seconds": (
                        self.config.frequency_window_seconds
                    ),
                    "frequency_window_start": (
                        window_starts[alert_object_id(alert)].isoformat()
                        if window_starts[alert_object_id(alert)] is not None
                        else None
                    ),
                },
            )
            for index, alert in enumerate(ordered, start=1)
        )
        result = GraphPrioritizationResult(
            graph_state=graph_state,
            ranked_alerts=ranked,
            candidates=tuple(item for item in ranked if item.forwarded),
        )
        if self.graph_store is None:
            return result
        return replace(result, persistence=self.graph_store.save(result))
