"""Paper-aligned bidirectional alert-graph context augmentation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from ...config import LLMInvestigationConfig
from ...models import (
    AlertGraphState,
    AlertObject,
    EvidenceItem,
    MetaAlert,
    NormalizedAlert,
    alert_object_entities,
    alert_object_id,
    alert_object_time,
)


class BidirectionalContextRetriever(Protocol):
    """Retrieve and prune behavior before and after a candidate alert."""

    def retrieve(
        self,
        alert: AlertObject,
        graph_state: AlertGraphState,
    ) -> tuple[tuple[EvidenceItem, ...], tuple[EvidenceItem, ...]]:
        """Return backward and forward evidence, respectively."""
        ...


def _end_time(alert: AlertObject) -> datetime:
    if isinstance(alert, NormalizedAlert):
        return alert.timestamp
    return alert.last_seen


def _services(alert: AlertObject) -> tuple[str, ...]:
    if isinstance(alert, NormalizedAlert):
        return (alert.service,) if alert.service else ()
    return alert.services


@dataclass(frozen=True, slots=True)
class _FrontierLink:
    """One deterministic path from the investigated alert to an entity."""

    parent_alert_id: str
    path_alert_ids: tuple[str, ...]
    path_entities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ContextCandidate:
    """An alert node together with its graph and temporal relevance."""

    alert: AlertObject
    hop: int
    parent_alert_id: str
    link_entity: str
    path_alert_ids: tuple[str, ...]
    path_entities: tuple[str, ...]
    distance_seconds: float
    relationship: str
    relation_priority: int
    shared_seed_entities: tuple[str, ...]
    shared_source_entities: tuple[str, ...]
    shared_target_entities: tuple[str, ...]
    transition_entities: tuple[str, ...]


def _candidate_rank(candidate: _ContextCandidate) -> tuple[object, ...]:
    """Rank explicit graph relations before hop count and temporal proximity."""

    return (
        -candidate.relation_priority,
        candidate.hop,
        candidate.distance_seconds,
        alert_object_id(candidate.alert),
        candidate.parent_alert_id,
        candidate.link_entity,
    )


def _relationship(
    current_sources: set[str],
    current_targets: set[str],
    seed_entities: set[str],
    candidate: AlertObject,
    temporal_role: str,
) -> tuple[
    str,
    int,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    """Describe the strongest paper-defined relation to the current alert."""

    candidate_sources, candidate_targets = alert_object_entities(candidate)
    candidate_source_set = set(candidate_sources)
    candidate_target_set = set(candidate_targets)
    candidate_entities = candidate_source_set | candidate_target_set
    shared_seed = tuple(sorted(seed_entities & candidate_entities))
    shared_sources = tuple(sorted(current_sources & candidate_source_set))
    shared_targets = tuple(sorted(current_targets & candidate_target_set))
    if temporal_role == "forward":
        transitions = tuple(sorted(current_targets & candidate_source_set))
    else:
        transitions = tuple(sorted(candidate_target_set & current_sources))

    if shared_sources and shared_targets:
        relationship, priority = "same_source_target_pair", 5
    elif transitions:
        relationship, priority = (
            "target_to_source_progression"
            if temporal_role == "forward"
            else "predecessor_to_source_progression"
        ), 4
    elif shared_targets:
        relationship, priority = "shared_target", 3
    elif shared_sources:
        relationship, priority = "shared_source", 3
    elif shared_seed:
        relationship, priority = "shared_seed_entity", 2
    else:
        relationship, priority = "transitive_graph_path", 1
    return (
        relationship,
        priority,
        shared_seed,
        shared_sources,
        shared_targets,
        transitions,
    )


def _temporal_distance(
    candidate: AlertObject,
    *,
    temporal_role: str,
    current_start: datetime,
    current_end: datetime,
    window_seconds: int,
) -> float | None:
    candidate_start = alert_object_time(candidate)
    candidate_end = _end_time(candidate)
    if temporal_role == "backward":
        if candidate_end >= current_start:
            return None
        distance = (current_start - candidate_end).total_seconds()
    else:
        if candidate_start <= current_end:
            return None
        distance = (candidate_start - current_end).total_seconds()
    return distance if distance <= window_seconds else None


def _continues_path(
    candidate: AlertObject,
    parent: AlertObject,
    temporal_role: str,
) -> bool:
    """Require every multi-hop path to preserve chronological direction."""

    if temporal_role == "backward":
        return _end_time(candidate) < alert_object_time(parent)
    return alert_object_time(candidate) > _end_time(parent)


def _evidence_item(
    candidate: _ContextCandidate,
    temporal_role: str,
    relevance_rank: int,
) -> EvidenceItem:
    alert = candidate.alert
    identifier = alert_object_id(alert)
    sources, targets = alert_object_entities(alert)
    digest = hashlib.sha256(
        f"{temporal_role}:{identifier}".encode("utf-8")
    ).hexdigest()[:20]
    details: dict[str, object] = {
        "alert_id": identifier,
        "object_type": "meta_alert" if isinstance(alert, MetaAlert) else "alert",
        "start_time": alert_object_time(alert).isoformat(),
        "end_time": _end_time(alert).isoformat(),
        "source_entities": sources,
        "target_entities": targets,
        "services": _services(alert),
        "distance_seconds": candidate.distance_seconds,
        "member_count": (
            len(alert.member_alert_ids) if isinstance(alert, MetaAlert) else 1
        ),
        "graph_hop": candidate.hop,
        "parent_alert_id": candidate.parent_alert_id,
        "link_entity": candidate.link_entity,
        "path_alert_ids": candidate.path_alert_ids,
        "path_entities": candidate.path_entities,
        "relationship": candidate.relationship,
        "relation_priority": candidate.relation_priority,
        "relevance_rank": relevance_rank,
        "shared_seed_entities": candidate.shared_seed_entities,
        "shared_source_entities": candidate.shared_source_entities,
        "shared_target_entities": candidate.shared_target_entities,
        "transition_entities": candidate.transition_entities,
    }
    if isinstance(alert, MetaAlert):
        details["behavior_statistics"] = dict(alert.statistics)
    return EvidenceItem(
        evidence_id=f"ev-{digest}",
        temporal_role=temporal_role,
        timestamp=alert_object_time(alert),
        alert_semantics=alert.alert_semantics,
        entities=tuple(sorted(set(sources + targets))),
        details=details,
    )


class GraphBidirectionalContextRetriever:
    """Construct a bounded, path-preserving relevant alert subgraph."""

    def __init__(self, config: LLMInvestigationConfig | None = None) -> None:
        self.config = config or LLMInvestigationConfig()

    def _collect_direction(
        self,
        alert: AlertObject,
        graph_state: AlertGraphState,
        temporal_role: str,
    ) -> tuple[EvidenceItem, ...]:
        current_id = alert_object_id(alert)
        current_start = alert_object_time(alert)
        current_end = _end_time(alert)
        sources, targets = alert_object_entities(alert)
        current_sources = set(sources)
        current_targets = set(targets)
        all_seed_entities = current_sources | current_targets

        # Backward retrieval uses every seed entity. Forward retrieval starts
        # from the target/affected entity and falls back to the source only when
        # endpoint telemetry has no explicit target field.
        traversal_seeds = (
            current_targets
            if temporal_role == "forward" and current_targets
            else all_seed_entities
        )
        if not traversal_seeds:
            return ()

        window_seconds = (
            self.config.backward_window_seconds
            if temporal_role == "backward"
            else self.config.forward_window_seconds
        )
        frontier = {
            entity: _FrontierLink(
                parent_alert_id=current_id,
                path_alert_ids=(current_id,),
                path_entities=(),
            )
            for entity in sorted(traversal_seeds)
        }
        visited_entities: set[str] = set()
        candidates: dict[str, _ContextCandidate] = {}

        for hop in range(1, self.config.context_max_hops + 1):
            if not frontier:
                break
            visited_entities.update(frontier)
            discovered: dict[str, _ContextCandidate] = {}
            for link_entity, link in sorted(frontier.items()):
                parent = graph_state.alerts_by_id[link.parent_alert_id]
                for identifier in graph_state.entity_to_alert_ids.get(link_entity, ()):
                    if identifier == current_id:
                        continue
                    related = graph_state.alerts_by_id[identifier]
                    distance = _temporal_distance(
                        related,
                        temporal_role=temporal_role,
                        current_start=current_start,
                        current_end=current_end,
                        window_seconds=window_seconds,
                    )
                    if distance is None or not _continues_path(
                        related,
                        parent,
                        temporal_role,
                    ):
                        continue
                    (
                        relationship,
                        priority,
                        shared_seed,
                        shared_sources,
                        shared_targets,
                        transitions,
                    ) = _relationship(
                        current_sources,
                        current_targets,
                        all_seed_entities,
                        related,
                        temporal_role,
                    )
                    candidate = _ContextCandidate(
                        alert=related,
                        hop=hop,
                        parent_alert_id=link.parent_alert_id,
                        link_entity=link_entity,
                        path_alert_ids=link.path_alert_ids + (identifier,),
                        path_entities=link.path_entities + (link_entity,),
                        distance_seconds=distance,
                        relationship=relationship,
                        relation_priority=priority,
                        shared_seed_entities=shared_seed,
                        shared_source_entities=shared_sources,
                        shared_target_entities=shared_targets,
                        transition_entities=transitions,
                    )
                    existing = candidates.get(identifier)
                    if existing is not None and _candidate_rank(existing) <= _candidate_rank(
                        candidate
                    ):
                        continue
                    candidates[identifier] = candidate
                    discovered[identifier] = candidate

            # Expanding only a bounded best frontier prevents a high-degree
            # enterprise entity from exploding the context search.
            expansion_limit = self.config.max_context_items_per_direction
            next_frontier: dict[str, _FrontierLink] = {}
            for candidate in sorted(
                discovered.values(),
                key=_candidate_rank,
            )[:expansion_limit]:
                candidate_sources, candidate_targets = alert_object_entities(
                    candidate.alert
                )
                for entity in sorted(set(candidate_sources + candidate_targets)):
                    if entity in visited_entities:
                        continue
                    proposed = _FrontierLink(
                        parent_alert_id=alert_object_id(candidate.alert),
                        path_alert_ids=candidate.path_alert_ids,
                        path_entities=candidate.path_entities,
                    )
                    existing_link = next_frontier.get(entity)
                    if existing_link is None or (
                        proposed.parent_alert_id,
                        proposed.path_alert_ids,
                    ) < (
                        existing_link.parent_alert_id,
                        existing_link.path_alert_ids,
                    ):
                        next_frontier[entity] = proposed
            frontier = next_frontier

        if not candidates:
            return ()

        # Keep each selected multi-hop node together with its ancestors so the
        # serialized evidence remains a connected minimum relevant subgraph.
        limit = self.config.max_context_items_per_direction
        selected: dict[str, _ContextCandidate] = {}
        for candidate in sorted(candidates.values(), key=_candidate_rank):
            chain = [
                candidates[identifier]
                for identifier in candidate.path_alert_ids[1:]
                if identifier in candidates and identifier not in selected
            ]
            if len(selected) + len(chain) > limit:
                continue
            for item in chain:
                selected[alert_object_id(item.alert)] = item
            if len(selected) == limit:
                break

        rank_by_id = {
            alert_object_id(candidate.alert): rank
            for rank, candidate in enumerate(
                sorted(candidates.values(), key=_candidate_rank),
                start=1,
            )
        }
        # Emit the chosen set chronologically for coherent LLM reasoning while
        # retaining the graph-pruning order in relevance_rank.
        ordered = sorted(
            selected.values(),
            key=lambda item: (
                alert_object_time(item.alert),
                _end_time(item.alert),
                alert_object_id(item.alert),
            ),
        )
        return tuple(
            _evidence_item(
                candidate,
                temporal_role,
                rank_by_id[alert_object_id(candidate.alert)],
            )
            for candidate in ordered
        )

    def retrieve(
        self,
        alert: AlertObject,
        graph_state: AlertGraphState,
    ) -> tuple[tuple[EvidenceItem, ...], tuple[EvidenceItem, ...]]:
        current_id = alert_object_id(alert)
        if current_id not in graph_state.alerts_by_id:
            raise ValueError(
                f"investigated alert is absent from graph state: {current_id}"
            )
        return (
            self._collect_direction(alert, graph_state, "backward"),
            self._collect_direction(alert, graph_state, "forward"),
        )
