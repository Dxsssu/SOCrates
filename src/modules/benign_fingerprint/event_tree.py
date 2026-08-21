"""Six-level Hierarchical Alert Event Tree (HAT)."""

from __future__ import annotations

import ipaddress
import json
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Iterator, Protocol, runtime_checkable

from ...models import AlertObject, MetaAlert
from .attribute_template import (
    EMPTY_ATTRIBUTE_TEMPLATE,
    AttributeTemplateExtractor,
    PayloadAttributeTemplateExtractor,
)


NULL_VALUE = "<NULL>"
MULTIPLE_VALUE = "<MULTIPLE>"


class AlertLayer(str, Enum):
    """The fixed root-to-leaf order of a Hierarchical Alert Event Tree."""

    ALERT_SOURCE = "alert_source"
    ALERT_SEMANTICS = "alert_semantics"
    SOURCE_ENTITY = "source_entity"
    TARGET_ENTITY = "target_entity"
    SERVICE_INFORMATION = "service_information"
    ATTRIBUTE_TEMPLATE = "attribute_template"


LAYER_ORDER = (
    AlertLayer.ALERT_SOURCE,
    AlertLayer.ALERT_SEMANTICS,
    AlertLayer.SOURCE_ENTITY,
    AlertLayer.TARGET_ENTITY,
    AlertLayer.SERVICE_INFORMATION,
    AlertLayer.ATTRIBUTE_TEMPLATE,
)


def canonicalize_layer_value(value: object | None) -> str:
    """Return a stable tree value without changing its semantic case."""

    if value is None:
        return NULL_VALUE
    normalized = unicodedata.normalize("NFKC", str(value))
    normalized = " ".join(normalized.split())
    return normalized if normalized else NULL_VALUE


def canonicalize_entity_value(
    value: object | None,
    ipv4_prefix_length: int | None = None,
    ipv6_prefix_length: int | None = None,
) -> str:
    """Canonicalize an entity and optionally group IP addresses by subnet."""

    canonical = canonicalize_layer_value(value)
    if canonical == NULL_VALUE:
        return canonical
    try:
        address = ipaddress.ip_address(canonical)
    except ValueError:
        return canonical
    prefix_length = ipv4_prefix_length if address.version == 4 else ipv6_prefix_length
    if prefix_length is None:
        return canonical
    return str(ipaddress.ip_network((address, prefix_length), strict=False))


@dataclass(frozen=True, slots=True)
class AlertPath:
    """Named representation of the six fixed HAT layers."""

    alert_source: str
    alert_semantics: str
    source_entity: str
    target_entity: str
    service_information: str
    attribute_template: str = EMPTY_ATTRIBUTE_TEMPLATE

    @classmethod
    def from_alert(
        cls,
        alert: AlertObject,
        template_extractor: AttributeTemplateExtractor | None = None,
        entity_ipv4_prefix_length: int | None = None,
        entity_ipv6_prefix_length: int | None = None,
    ) -> "AlertPath":
        """Build a path with a detector-payload-derived attribute template."""

        extractor = template_extractor or PayloadAttributeTemplateExtractor(
            generalize_dynamic_values=False
        )
        if isinstance(alert, MetaAlert):
            sources = alert.source_entities
            targets = alert.target_entities
            services = alert.services

            def collapse(values: tuple[str, ...]) -> str:
                if not values:
                    return NULL_VALUE
                return values[0] if len(values) == 1 else MULTIPLE_VALUE

            source_value = collapse(sources)
            target_value = collapse(targets)
            service_value = collapse(services)
            stable_statistics = {
                key: alert.statistics[key]
                for key in (
                    "aggregation_stage",
                    "behavior_category",
                    "behavior_family",
                    "detection_signal",
                    "scan_family",
                    "member_count_bucket",
                    "duration_bucket",
                    "event_rate_bucket",
                    "distinct_source_count_bucket",
                    "distinct_target_count_bucket",
                    "distinct_service_count_bucket",
                    "distinct_destination_port_count_bucket",
                    "distinct_resource_count_bucket",
                    "normalized_behavior_template",
                    "member_alert_sources",
                    "member_alert_semantics",
                )
                if key in alert.statistics
            }
            return cls(
                alert_source=canonicalize_layer_value(alert.alert_source),
                alert_semantics=canonicalize_layer_value(alert.alert_semantics),
                source_entity=canonicalize_entity_value(
                    source_value,
                    entity_ipv4_prefix_length,
                    entity_ipv6_prefix_length,
                ),
                target_entity=canonicalize_entity_value(
                    target_value,
                    entity_ipv4_prefix_length,
                    entity_ipv6_prefix_length,
                ),
                service_information=canonicalize_layer_value(service_value),
                attribute_template=json.dumps(
                    stable_statistics,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ),
            )
        return cls(
            alert_source=canonicalize_layer_value(alert.alert_source),
            alert_semantics=canonicalize_layer_value(alert.alert_semantics),
            source_entity=canonicalize_entity_value(
                alert.source_entity,
                entity_ipv4_prefix_length,
                entity_ipv6_prefix_length,
            ),
            target_entity=canonicalize_entity_value(
                alert.target_entity,
                entity_ipv4_prefix_length,
                entity_ipv6_prefix_length,
            ),
            service_information=canonicalize_layer_value(alert.service),
            attribute_template=extractor.extract(alert),
        )

    @property
    def values(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.alert_source,
            self.alert_semantics,
            self.source_entity,
            self.target_entity,
            self.service_information,
            self.attribute_template,
        )

    def __iter__(self) -> Iterator[str]:
        return iter(self.values)

    def __len__(self) -> int:
        return len(LAYER_ORDER)

    def as_dict(self) -> dict[str, str]:
        return {
            layer.value: value
            for layer, value in zip(LAYER_ORDER, self.values, strict=True)
        }


@dataclass(slots=True)
class AlertTreeNode:
    """One value node in the HAT."""

    layer: AlertLayer | None
    value: str
    support: int = 0
    terminal_support: int = 0
    children: dict[str, "AlertTreeNode"] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "layer": self.layer.value if self.layer is not None else "root",
            "value": self.value,
            "support": self.support,
            "terminal_support": self.terminal_support,
            "children": [self.children[key].to_dict() for key in sorted(self.children)],
        }


@dataclass(frozen=True, slots=True)
class TreeMatch:
    """Result of traversing a complete or partial HAT path."""

    matched: bool
    matched_depth: int
    support: int
    terminal_support: int
    missing_layer: AlertLayer | None = None


@runtime_checkable
class AlertEventTree(Protocol):
    """Interface required by benign fingerprint filtering."""

    def path_for(self, alert: AlertObject) -> AlertPath:
        """Map a normalized alert to its six-level HAT path."""
        ...

    def insert(self, path: AlertPath, count: int = 1) -> None:
        """Insert an analyst-verified benign path."""
        ...

    def contains(self, path: AlertPath, minimum_support: int = 1) -> bool:
        """Return whether an exact leaf has sufficient support."""
        ...

    def match(self, path: AlertPath) -> TreeMatch:
        """Traverse a path and return auditable match details."""
        ...


class HierarchicalAlertEventTree:
    """In-memory, thread-safe implementation of the six-level HAT."""

    def __init__(
        self,
        template_extractor: AttributeTemplateExtractor | None = None,
        *,
        entity_ipv4_prefix_length: int | None = None,
        entity_ipv6_prefix_length: int | None = None,
    ) -> None:
        self._root = AlertTreeNode(layer=None, value="<ROOT>")
        self._node_count = 1
        self._path_count = 0
        self._lock = RLock()
        self.template_extractor = (
            template_extractor
            or PayloadAttributeTemplateExtractor(generalize_dynamic_values=False)
        )
        self.entity_ipv4_prefix_length = entity_ipv4_prefix_length
        self.entity_ipv6_prefix_length = entity_ipv6_prefix_length

    @property
    def root(self) -> AlertTreeNode:
        return self._root

    @property
    def node_count(self) -> int:
        """Number of nodes including the root node."""

        with self._lock:
            return self._node_count

    @property
    def path_count(self) -> int:
        """Number of distinct complete benign paths."""

        with self._lock:
            return self._path_count

    @property
    def total_support(self) -> int:
        with self._lock:
            return self._root.support

    def path_for(self, alert: AlertObject) -> AlertPath:
        return AlertPath.from_alert(
            alert,
            self.template_extractor,
            self.entity_ipv4_prefix_length,
            self.entity_ipv6_prefix_length,
        )

    def insert(self, path: AlertPath, count: int = 1) -> None:
        if count < 1:
            raise ValueError("count must be at least 1")

        with self._lock:
            node = self._root
            node.support += count
            for layer, value in zip(LAYER_ORDER, path.values, strict=True):
                child = node.children.get(value)
                if child is None:
                    child = AlertTreeNode(layer=layer, value=value)
                    node.children[value] = child
                    self._node_count += 1
                child.support += count
                node = child

            if node.terminal_support == 0:
                self._path_count += 1
            node.terminal_support += count

    def match(self, path: AlertPath) -> TreeMatch:
        with self._lock:
            node = self._root
            for depth, (layer, value) in enumerate(
                zip(LAYER_ORDER, path.values, strict=True), start=1
            ):
                child = node.children.get(value)
                if child is None:
                    return TreeMatch(
                        matched=False,
                        matched_depth=depth - 1,
                        support=node.support,
                        terminal_support=0,
                        missing_layer=layer,
                    )
                node = child

            return TreeMatch(
                matched=node.terminal_support > 0,
                matched_depth=len(LAYER_ORDER),
                support=node.support,
                terminal_support=node.terminal_support,
                missing_layer=None,
            )

    def contains(self, path: AlertPath, minimum_support: int = 1) -> bool:
        if minimum_support < 1:
            raise ValueError("minimum_support must be at least 1")
        result = self.match(path)
        return result.matched and result.terminal_support >= minimum_support

    def support(self, path: AlertPath) -> int:
        return self.match(path).terminal_support

    def paths(self) -> tuple[tuple[AlertPath, int], ...]:
        """Return every terminal path and support in deterministic order."""

        result: list[tuple[AlertPath, int]] = []

        def visit(node: AlertTreeNode, values: tuple[str, ...]) -> None:
            if len(values) == len(LAYER_ORDER):
                if node.terminal_support > 0:
                    result.append((AlertPath(*values), node.terminal_support))
                return
            for value in sorted(node.children):
                visit(node.children[value], (*values, value))

        with self._lock:
            visit(self._root, ())
        return tuple(result)

    def to_dict(self) -> dict:
        """Return a deterministic, JSON-serializable tree snapshot."""

        with self._lock:
            return {
                "layers": [layer.value for layer in LAYER_ORDER],
                "node_count": self._node_count,
                "path_count": self._path_count,
                "total_support": self._root.support,
                "root": self._root.to_dict(),
            }

    def clear(self) -> None:
        with self._lock:
            self._root = AlertTreeNode(layer=None, value="<ROOT>")
            self._node_count = 1
            self._path_count = 0
