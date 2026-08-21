"""Paper-aligned normalized alert patterns for graph prioritization."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from ...models import AlertObject, MetaAlert, NormalizedAlert
from ..benign_fingerprint.attribute_template import PayloadAttributeTemplateExtractor


NULL_PATTERN_VALUE = "<NULL>"
_PROTOCOL_KEYS = ("protocol", "proto", "app_proto", "transport_protocol")
_SOURCE_PORT_KEYS = ("source_port", "src_port", "srcport", "sport")
_DESTINATION_PORT_KEYS = (
    "destination_port",
    "dest_port",
    "dst_port",
    "dstport",
    "dport",
)
_KNOWN_PROTOCOLS = {
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "http",
    "https",
    "dns",
    "tls",
    "ssh",
    "smtp",
    "imap",
    "pop3",
    "ftp",
}
_META_PATTERN_FIELDS = (
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
    "member_alert_sources",
    "member_alert_semantics",
    "normalized_behavior_template",
)


def _canonical_values(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(value).strip().casefold()
                for value in values
                if value not in (None, "") and str(value).strip()
            }
        )
    )


def _attribute_values(
    attributes: Mapping[str, object],
    keys: tuple[str, ...],
) -> tuple[str, ...]:
    values: list[object] = []
    for key in keys:
        value = attributes.get(key)
        if isinstance(value, (tuple, list, set)):
            values.extend(value)
        elif value not in (None, ""):
            values.append(value)
    return _canonical_values(values)


def _protocols_from_services(services: tuple[str, ...]) -> tuple[str, ...]:
    protocols: list[str] = []
    for service in services:
        protocols.extend(
            candidate
            for candidate in re.split(r"[/:\s]+", service.casefold())
            if candidate in _KNOWN_PROTOCOLS
        )
    return _canonical_values(protocols)


def alert_services(alert: AlertObject) -> tuple[str, ...]:
    """Return normalized service values used by pattern and relation keys."""

    if isinstance(alert, NormalizedAlert):
        return _canonical_values((alert.service,))
    return _canonical_values(alert.services)


def alert_protocols(alert: AlertObject) -> tuple[str, ...]:
    """Return explicit protocols, falling back to protocol-like services."""

    services = alert_services(alert)
    if isinstance(alert, NormalizedAlert):
        explicit = _attribute_values(alert.attributes, _PROTOCOL_KEYS)
        return explicit or _protocols_from_services(services)
    explicit = alert.statistics.get("protocols")
    if isinstance(explicit, (tuple, list, set)):
        normalized = _canonical_values(explicit)
        if normalized:
            return normalized
    if explicit not in (None, ""):
        return _canonical_values((explicit,))
    return _protocols_from_services(services)


def alert_ports(
    alert: AlertObject,
    *,
    role: str,
) -> tuple[str, ...]:
    """Return normalized source or destination ports for graph-node metadata."""

    if role not in {"source", "destination"}:
        raise ValueError("port role must be 'source' or 'destination'")
    keys = _SOURCE_PORT_KEYS if role == "source" else _DESTINATION_PORT_KEYS
    if isinstance(alert, NormalizedAlert):
        ports = _attribute_values(alert.attributes, keys)
        if ports or role == "source" or not alert.service:
            return ports
        service_port = re.search(r"[/:-](\d+)$", alert.service.strip())
        return (service_port.group(1),) if service_port is not None else ()
    statistic_key = "source_ports" if role == "source" else "destination_ports"
    value = alert.statistics.get(statistic_key)
    if isinstance(value, (tuple, list, set)):
        return _canonical_values(value)
    if value not in (None, ""):
        return _canonical_values((value,))
    return ()


@dataclass(frozen=True, slots=True)
class GraphAlertPattern:
    """Normalized alert pattern used for paper-defined frequency counting."""

    alert_source: str
    alert_semantics: str
    protocols: tuple[str, ...]
    services: tuple[str, ...]
    attribute_template: str

    @property
    def key(self) -> tuple[object, ...]:
        """Return the paper-defined behavioral pattern identity.

        ``alert_source`` remains available as node metadata, but is not part of
        the frequency key: Module 2 defines a normalized pattern by semantics,
        protocol, service, and attribute template.
        """

        return (
            self.alert_semantics,
            self.protocols,
            self.services,
            self.attribute_template,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "alert_source": self.alert_source,
            "alert_semantics": self.alert_semantics,
            "protocols": self.protocols,
            "services": self.services,
            "attribute_template": self.attribute_template,
        }


class GraphAlertPatternExtractor:
    """Build the same normalized pattern for scoring and persistence."""

    def __init__(self, numeric_min_digits: int | None = 3) -> None:
        self.template_extractor = PayloadAttributeTemplateExtractor(
            numeric_min_digits=numeric_min_digits,
            generalize_dynamic_values=True,
        )

    @staticmethod
    def _meta_template(alert: MetaAlert) -> str:
        stable_statistics = {
            key: alert.statistics[key]
            for key in _META_PATTERN_FIELDS
            if key in alert.statistics
        }
        return json.dumps(
            stable_statistics,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

    def extract(self, alert: AlertObject) -> GraphAlertPattern:
        attribute_template = (
            self.template_extractor.extract(alert)
            if isinstance(alert, NormalizedAlert)
            else self._meta_template(alert)
        )
        return GraphAlertPattern(
            alert_source=" ".join(str(alert.alert_source).split()).casefold(),
            alert_semantics=" ".join(str(alert.alert_semantics).split()).casefold(),
            protocols=alert_protocols(alert),
            services=alert_services(alert),
            attribute_template=attribute_template or NULL_PATTERN_VALUE,
        )
