"""Heterogeneous alert graph construction contracts."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Mapping, Protocol

from ...models import (
    AlertGraphState,
    AlertObject,
    MetaAlert,
    NormalizedAlert,
    alert_object_entities,
    alert_object_id,
)


class AlertGraphBuilder(Protocol):
    """Build directed alert/entity graphs while preserving event roles."""

    def build(
        self,
        alerts: Iterable[AlertObject],
        original_alerts_by_id: Mapping[str, NormalizedAlert] | None = None,
    ) -> AlertGraphState:
        """Construct and return a graph state for the supplied alerts."""
        ...

    def replace_alerts(
        self,
        graph_state: AlertGraphState,
        alerts: Iterable[AlertObject],
    ) -> AlertGraphState:
        """Replace graph alert nodes after optional input preparation."""
        ...


class InMemoryAlertGraphBuilder:
    """Construct deterministic alert/entity adjacency indexes in memory."""

    def _state(
        self,
        alerts: Iterable[AlertObject],
        originals: dict[str, NormalizedAlert],
    ) -> AlertGraphState:
        alerts_by_id: dict[str, AlertObject] = {}
        sources_by_id: dict[str, tuple[str, ...]] = {}
        targets_by_id: dict[str, tuple[str, ...]] = {}
        entity_index: dict[str, list[str]] = defaultdict(list)
        member_to_aggregate: dict[str, str] = {}

        for alert in alerts:
            identifier = alert_object_id(alert)
            if identifier in alerts_by_id:
                raise ValueError(f"duplicate alert identifier: {identifier}")
            sources, targets = alert_object_entities(alert)
            alerts_by_id[identifier] = alert
            sources_by_id[identifier] = tuple(sorted(set(sources)))
            targets_by_id[identifier] = tuple(sorted(set(targets)))
            for entity in sorted(set(sources + targets)):
                entity_index[entity].append(identifier)
            if isinstance(alert, MetaAlert):
                for member_id in alert.member_alert_ids:
                    member_to_aggregate[member_id] = identifier
            else:
                member_to_aggregate[identifier] = identifier

        return AlertGraphState(
            alerts_by_id=alerts_by_id,
            original_alerts_by_id=originals,
            source_entities=sources_by_id,
            target_entities=targets_by_id,
            entity_to_alert_ids={
                entity: tuple(sorted(identifiers))
                for entity, identifiers in sorted(entity_index.items())
            },
            member_to_aggregate=member_to_aggregate,
        )

    def build(
        self,
        alerts: Iterable[AlertObject],
        original_alerts_by_id: Mapping[str, NormalizedAlert] | None = None,
    ) -> AlertGraphState:
        alert_batch = tuple(alerts)
        originals = dict(original_alerts_by_id or {})
        for alert in alert_batch:
            if isinstance(alert, NormalizedAlert):
                originals.setdefault(alert.alert_id, alert)
        return self._state(alert_batch, originals)

    def replace_alerts(
        self,
        graph_state: AlertGraphState,
        alerts: Iterable[AlertObject],
    ) -> AlertGraphState:
        return self._state(alerts, dict(graph_state.original_alerts_by_id))
