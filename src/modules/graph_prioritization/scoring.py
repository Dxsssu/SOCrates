"""Graph anomaly scoring contracts."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable, Mapping, Protocol

from ...config import GraphPrioritizationConfig
from ...models import (
    AlertGraphState,
    AlertObject,
    AnomalyScore,
    alert_object_id,
    alert_object_time,
)
from .pattern import GraphAlertPattern, GraphAlertPatternExtractor


class GraphAnomalyScorer(Protocol):
    """Score alert patterns, entities, and complete relations."""

    def score(
        self,
        alerts: Iterable[AlertObject],
        graph_state: AlertGraphState,
    ) -> Mapping[str, AnomalyScore]:
        """Return an anomaly-score mapping keyed by alert identifier."""
        ...


def _relation_key(
    pattern: GraphAlertPattern,
    sources: tuple[str, ...],
    targets: tuple[str, ...],
) -> tuple[object, ...]:
    """Represent the complete directed source-pattern-target relation."""

    return (
        tuple(sorted(sources)),
        pattern.key,
        tuple(sorted(targets)),
    )


def frequency_window_start(
    alert: AlertObject,
    window_seconds: int | None,
) -> datetime | None:
    """Return the UTC-anchored scoring-window start for one alert object."""

    if window_seconds is None:
        return None
    timestamp = alert_object_time(alert)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    epoch_seconds = int(timestamp.timestamp())
    start_seconds = (epoch_seconds // window_seconds) * window_seconds
    return datetime.fromtimestamp(start_seconds, tz=timezone.utc)


def _inverse_frequency_scores(values: Mapping[str, float]) -> dict[str, float]:
    if not values:
        return {}
    minimum = min(values.values())
    maximum = max(values.values())
    if maximum == minimum:
        return {identifier: 1.0 for identifier in values}
    span = maximum - minimum
    return {
        identifier: 1.0 - ((value - minimum) / span)
        for identifier, value in values.items()
    }


class FrequencyGraphAnomalyScorer:
    """Paper-aligned inverse-frequency scorer with conservative degeneracy."""

    def __init__(self, config: GraphPrioritizationConfig | None = None) -> None:
        self.config = config or GraphPrioritizationConfig()
        self.pattern_extractor = GraphAlertPatternExtractor(
            self.config.pattern_numeric_min_digits
        )

    def score(
        self,
        alerts: Iterable[AlertObject],
        graph_state: AlertGraphState,
    ) -> Mapping[str, AnomalyScore]:
        alert_batch = tuple(alerts)
        identifiers = tuple(alert_object_id(alert) for alert in alert_batch)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("cannot score duplicate alert identifiers")
        missing = set(identifiers) - set(graph_state.alerts_by_id)
        if missing:
            raise ValueError(
                "graph state is missing alerts required for scoring: "
                + ", ".join(sorted(missing))
            )
        patterns = {
            alert_object_id(alert): self.pattern_extractor.extract(alert)
            for alert in alert_batch
        }
        windowed_alerts: dict[datetime | None, list[AlertObject]] = defaultdict(list)
        for alert in alert_batch:
            windowed_alerts[
                frequency_window_start(
                    alert,
                    self.config.frequency_window_seconds,
                )
            ].append(alert)

        pattern_scores: dict[str, float] = {}
        entity_scores: dict[str, float] = {}
        relation_scores: dict[str, float] = {}
        for window_start in sorted(
            windowed_alerts,
            key=lambda value: value or datetime.min.replace(tzinfo=timezone.utc),
        ):
            window_alerts = tuple(windowed_alerts[window_start])
            pattern_counts = Counter(
                patterns[alert_object_id(alert)].key for alert in window_alerts
            )
            relation_counts: Counter[tuple[object, ...]] = Counter()
            entity_counts: Counter[str] = Counter()
            for alert in window_alerts:
                identifier = alert_object_id(alert)
                sources = graph_state.source_entities[identifier]
                targets = graph_state.target_entities[identifier]
                entity_counts.update(set(sources + targets))
                relation_counts[
                    _relation_key(patterns[identifier], sources, targets)
                ] += 1

            window_pattern_frequency: dict[str, float] = {}
            window_relation_frequency: dict[str, float] = {}
            window_entity_frequency: dict[str, float] = {}
            for alert in window_alerts:
                identifier = alert_object_id(alert)
                sources = graph_state.source_entities[identifier]
                targets = graph_state.target_entities[identifier]
                entities = tuple(sorted(set(sources + targets)))
                pattern_value = float(pattern_counts[patterns[identifier].key])
                relation_value = float(
                    relation_counts[
                        _relation_key(patterns[identifier], sources, targets)
                    ]
                )
                entity_value = (
                    sum(entity_counts[entity] for entity in entities) / len(entities)
                    if entities
                    else 1.0
                )
                window_pattern_frequency[identifier] = pattern_value
                window_relation_frequency[identifier] = relation_value
                window_entity_frequency[identifier] = entity_value

            pattern_scores.update(
                _inverse_frequency_scores(window_pattern_frequency)
            )
            relation_scores.update(
                _inverse_frequency_scores(window_relation_frequency)
            )
            entity_scores.update(_inverse_frequency_scores(window_entity_frequency))
        result: dict[str, AnomalyScore] = {}
        for alert in alert_batch:
            identifier = alert_object_id(alert)
            alert_score = pattern_scores[identifier]
            entity_score = entity_scores[identifier]
            relation_score = relation_scores[identifier]
            total = (
                self.config.alert_weight * alert_score
                + self.config.entity_weight * entity_score
                + self.config.relation_weight * relation_score
            )
            result[identifier] = AnomalyScore(
                alert_pattern=alert_score,
                entity=entity_score,
                relation=relation_score,
                total=total,
            )
        return result
