"""Label-free high-frequency behavior aggregation before HAT matching.

The first module owns burst compression because repeated malicious behavior is
not necessarily anomalous under an inverse-frequency graph score.  Detection
here never consults evaluation labels; it relies only on normalized detector
semantics, entities, services, and payload evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping, Protocol

from ...models import (
    AlertObject,
    MetaAlert,
    NormalizedAlert,
    Stage1AggregationResult,
)


EXPLICIT_SCAN_MARKERS = (
    "scan",
    "probe",
    "probing",
    "sweep",
    "enumeration",
    "dirb",
    "wpscan",
    "gobuster",
    "nikto",
)
WEB_SCAN_MARKERS = (
    "web server 400 error",
    "web server 401 error",
    "web server 403 error",
    "web server 404 error",
    "multiple web server",
)
PROTOCOL_ANOMALY_MARKERS = (
    "invalid record",
    "invalid handshake",
    "invalid reply",
    "no server welcome",
    "unable to match response",
)
BRUTE_FORCE_MARKERS = (
    "brute force",
    "bruteforce",
    "password guess",
    "password guessing",
    "password spray",
    "login fail",
    "authentication fail",
    "multiple failed",
    "repeated failed",
    "invalid user",
    "online cracking",
)
DNS_TUNNEL_MARKERS = (
    "dns tunnel",
    "dns tunneling",
    "dns exfil",
    "dns data exfiltration",
    "dnsteal",
)
DENIAL_OF_SERVICE_MARKERS = (
    "denial of service",
    "dos attack",
    "ddos",
    "syn flood",
    "request flood",
    "connection flood",
)
DNS_NAME_KEYS = {"rrname", "qname", "query_name", "queryname", "hostname"}
APACHE_REQUEST_RE = re.compile(
    r'"(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)\s+\S+\s+HTTP/\d(?:\.\d)?"\s+'
    r"(?P<status>\d{3})\b",
    re.IGNORECASE,
)
LEADING_IP_RE = re.compile(r"^\s*(?P<ip>[0-9a-fA-F:.]+)\s")
APACHE_CLIENT_IP_RE = re.compile(
    r"\[client\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)(?::\d+)?\]",
    re.IGNORECASE,
)
WEAK_WEB_SCAN_MARKERS = (
    "new characters in apache access request",
    "new event type",
    "new status code in apache access log",
    "unusual occurrence frequencies of apache",
    "attempt to access forbidden file or directory",
    "attempt to access forbidden directory index",
    "suspicious url access",
    "common web attack",
    "web server 500 error",
)
DNS_TUNNEL_CONTROL_LABEL_RE = re.compile(r"^\d+x\d+-$", re.IGNORECASE)
DNS_TUNNEL_SEQUENCE_LABEL_RE = re.compile(r"^\d+-$")


@dataclass(frozen=True, slots=True)
class HighFrequencyBehavior:
    """A label-free behavior classification used only for aggregation."""

    category: str
    family: str
    signal: str
    include_target_in_key: bool


class AlertPreprocessor(Protocol):
    """Prepare raw normalized alerts for HAT insertion or matching."""

    def aggregate(
        self,
        alerts: Iterable[NormalizedAlert],
    ) -> Stage1AggregationResult:
        """Return raw alerts and traceable high-frequency meta-alerts."""
        ...


class IdentityAlertPreprocessor:
    """Compatibility preprocessor that leaves every alert unchanged."""

    def aggregate(
        self,
        alerts: Iterable[NormalizedAlert],
    ) -> Stage1AggregationResult:
        batch = tuple(alerts)
        originals = {alert.alert_id: alert for alert in batch}
        if len(originals) != len(batch):
            raise ValueError("normalized alerts contain duplicate alert IDs")
        return Stage1AggregationResult(
            alerts=batch,
            original_alerts_by_id=originals,
            member_to_aggregate={alert.alert_id: alert.alert_id for alert in batch},
        )


def _attribute_text(alert: NormalizedAlert) -> str:
    return json.dumps(
        alert.attributes,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    ).casefold()


def scan_family(alert: NormalizedAlert) -> str | None:
    """Infer a scan family from detector evidence without consulting labels."""

    semantics = alert.alert_semantics.casefold()
    attributes = _attribute_text(alert)
    combined = f"{semantics} {attributes}"
    if "wpscan" in combined:
        return "web_scan:wpscan"
    if any(marker in combined for marker in ("dirb", "gobuster", "nikto")):
        return "web_scan:enumeration"
    if any(marker in semantics for marker in WEB_SCAN_MARKERS):
        return "web_scan:enumeration"
    if "web_scan" in attributes or '"recon"' in attributes:
        return "web_scan:enumeration"
    apache_matches = (
        match
        for line in _raw_lines(alert)
        if (match := APACHE_REQUEST_RE.search(line)) is not None
    )
    if any(match.group("status").startswith("4") for match in apache_matches):
        return "web_scan:enumeration"
    if any(marker in combined for marker in EXPLICIT_SCAN_MARKERS):
        if "dns" in combined:
            return "dns_scan"
        if "service" in combined or "port" in combined:
            return "service_scan"
        return "network_scan"
    if any(marker in semantics for marker in PROTOCOL_ANOMALY_MARKERS):
        return "protocol_scan"
    return None


def brute_force_family(alert: NormalizedAlert) -> str | None:
    """Infer repeated credential-guessing behavior from detector evidence."""

    combined = f"{alert.alert_semantics.casefold()} {_attribute_text(alert)}"
    if not any(marker in combined for marker in BRUTE_FORCE_MARKERS):
        return None
    if "ssh" in combined or (alert.service and "ssh" in alert.service.casefold()):
        return "ssh_authentication"
    if "rdp" in combined or "remote desktop" in combined:
        return "rdp_authentication"
    if any(marker in combined for marker in ("http", "web", "wordpress", "wp-")):
        return "web_authentication"
    if any(marker in combined for marker in ("mail", "imap", "smtp", "pop3")):
        return "mail_authentication"
    return "authentication"


def _strings_below(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        result: list[str] = []
        for nested in value.values():
            result.extend(_strings_below(nested))
        return tuple(result)
    if isinstance(value, (list, tuple)):
        result = []
        for nested in value:
            result.extend(_strings_below(nested))
        return tuple(result)
    return ()


def _dns_query_names(alert: NormalizedAlert) -> tuple[str, ...]:
    names: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                normalized_key = str(key).casefold()
                if normalized_key in DNS_NAME_KEYS:
                    names.extend(_strings_below(nested))
                elif normalized_key == "query" and isinstance(nested, str):
                    names.append(nested)
                visit(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                visit(nested)

    visit(alert.attributes)
    return tuple(
        dict.fromkeys(name.strip().rstrip(".") for name in names if name.strip())
    )


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value.casefold():
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _encoded_dns_name(name: str) -> bool:
    labels = tuple(label for label in name.split(".") if label)
    if len(labels) < 3:
        return False
    if (
        len(labels) >= 2
        and DNS_TUNNEL_CONTROL_LABEL_RE.fullmatch(labels[0]) is not None
        and DNS_TUNNEL_SEQUENCE_LABEL_RE.fullmatch(labels[1]) is not None
    ):
        return True
    longest = max(labels, key=len)
    compact = re.sub(r"[^A-Za-z0-9+/=_*-]", "", longest)
    return (
        len(name) >= 80 and len(compact) >= 32 and _shannon_entropy(compact) >= 3.5
    ) or (len(name) >= 120 and len(compact) >= 24)


def _dns_base_domain(name: str) -> str:
    """Return a stable last-two-label grouping key for one DNS name."""

    labels = tuple(label.casefold() for label in name.split(".") if label)
    if len(labels) < 2:
        return name.casefold()
    return ".".join(labels[-2:])


def dns_tunnel_family(alert: NormalizedAlert) -> str | None:
    """Infer DNS-tunnel traffic using explicit markers or encoded qnames."""

    semantics = alert.alert_semantics.casefold()
    attributes = _attribute_text(alert)
    combined = f"{semantics} {attributes}"
    if any(marker in combined for marker in DNS_TUNNEL_MARKERS):
        return "explicit_tunnel"
    if not _is_dns_context(alert):
        return None
    encoded_names = tuple(
        name for name in _dns_query_names(alert) if _encoded_dns_name(name)
    )
    if encoded_names:
        base_domain = sorted({_dns_base_domain(name) for name in encoded_names})[0]
        return f"encoded_subdomain:{base_domain}"
    return None


def _is_dns_context(alert: NormalizedAlert) -> bool:
    semantics = alert.alert_semantics.casefold()
    service = (alert.service or "").casefold()
    protocol = str(alert.attributes.get("protocol") or "").casefold()
    destination_port = str(alert.attributes.get("destination_port") or "")
    source_port = str(alert.attributes.get("source_port") or "")
    return (
        "dns" in semantics
        or "dns" in service
        or protocol == "dns"
        or destination_port == "53"
        or source_port == "53"
    )


def denial_of_service_family(alert: NormalizedAlert) -> str | None:
    """Infer explicitly detected flooding behavior without using labels."""

    combined = f"{alert.alert_semantics.casefold()} {_attribute_text(alert)}"
    if not any(marker in combined for marker in DENIAL_OF_SERVICE_MARKERS):
        return None
    if "syn" in combined:
        return "syn_flood"
    if any(marker in combined for marker in ("http", "request", "web")):
        return "request_flood"
    return "traffic_flood"


def high_frequency_behavior(
    alert: NormalizedAlert,
) -> HighFrequencyBehavior | None:
    """Classify one alert into a supported high-frequency behavior family."""

    family = scan_family(alert)
    if family is not None:
        return HighFrequencyBehavior("scan", family, "scan_marker", False)
    family = brute_force_family(alert)
    if family is not None:
        return HighFrequencyBehavior(
            "brute_force",
            family,
            "credential_failure_marker",
            True,
        )
    family = dns_tunnel_family(alert)
    if family is not None:
        return HighFrequencyBehavior(
            "dns_tunnel",
            family,
            "dns_payload_heuristic",
            True,
        )
    family = denial_of_service_family(alert)
    if family is not None:
        return HighFrequencyBehavior(
            "denial_of_service",
            family,
            "flood_marker",
            True,
        )
    return None


def _raw_lines(alert: NormalizedAlert) -> tuple[str, ...]:
    payload = alert.attributes.get("payload_fields")
    if not isinstance(payload, Mapping):
        return ()
    lines: list[str] = []
    for field_name in ("raw_log_data", "full_log"):
        value = payload.get(field_name)
        if isinstance(value, str):
            lines.append(value)
        elif isinstance(value, (list, tuple)):
            lines.extend(str(item) for item in value)
    return tuple(dict.fromkeys(lines))


def _event_source(alert: NormalizedAlert) -> str:
    if alert.source_entity:
        return alert.source_entity
    for line in _raw_lines(alert):
        match = LEADING_IP_RE.match(line) or APACHE_CLIENT_IP_RE.search(line)
        if match is None:
            continue
        candidate = match.group("ip")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return "<NULL>"


def _is_web_context(alert: NormalizedAlert) -> bool:
    combined = (
        f"{alert.alert_semantics} {alert.service or ''} "
        f"{alert.attributes.get('log_resource') or ''} "
        f"{' '.join(_raw_lines(alert))}"
    ).casefold()
    return any(
        marker in combined
        for marker in ("apache", "http/", "web ", "url", "access.log", "error.log")
    )


def _weak_web_scan_candidate(alert: NormalizedAlert) -> bool:
    """Return whether an unclassified alert can extend a confirmed web scan.

    These deliberately weak detector semantics never start a scan on their
    own.  They are eligible only for correlation with a strong, label-free
    web-scan seed from the same source and target in the configured time
    window.
    """

    semantics = alert.alert_semantics.casefold()
    return _is_web_context(alert) and any(
        marker in semantics for marker in WEAK_WEB_SCAN_MARKERS
    )


def _web_scan_correlation_key(alert: NormalizedAlert) -> tuple[str, str] | None:
    source = _event_source(alert)
    target = alert.target_entity or "<NULL>"
    if source == "<NULL>" or target == "<NULL>":
        return None
    return source, target


def _is_web_scan_behavior(behavior: HighFrequencyBehavior | None) -> bool:
    return (
        behavior is not None
        and behavior.category == "scan"
        and behavior.family.startswith("web_scan:")
    )


def _correlate_web_scan_behaviors(
    alerts: tuple[NormalizedAlert, ...],
    direct_behaviors: Mapping[str, HighFrequencyBehavior | None],
    window_seconds: int,
) -> dict[str, HighFrequencyBehavior | None]:
    """Attach weak cross-detector web evidence to nearby confirmed scans."""

    seeds: dict[
        tuple[str, str],
        list[tuple[datetime, str, HighFrequencyBehavior]],
    ] = defaultdict(list)
    for alert in alerts:
        behavior = direct_behaviors[alert.alert_id]
        key = _web_scan_correlation_key(alert)
        if key is not None and _is_web_scan_behavior(behavior):
            seeds[key].append((alert.timestamp, alert.alert_id, behavior))
    for observations in seeds.values():
        observations.sort(key=lambda item: (item[0], item[1]))
    seed_timestamps = {
        key: [item[0] for item in observations]
        for key, observations in seeds.items()
    }

    resolved = dict(direct_behaviors)
    for alert in alerts:
        if resolved[alert.alert_id] is not None or not _weak_web_scan_candidate(alert):
            continue
        key = _web_scan_correlation_key(alert)
        observations = seeds.get(key) if key is not None else None
        if not observations:
            continue
        timestamps = seed_timestamps[key]
        insertion = bisect_left(timestamps, alert.timestamp)
        nearest = min(
            observations[max(0, insertion - 1) : min(len(observations), insertion + 1)],
            key=lambda item: (
                abs((item[0] - alert.timestamp).total_seconds()),
                item[0],
                item[1],
            ),
        )
        if abs((nearest[0] - alert.timestamp).total_seconds()) > window_seconds:
            continue
        resolved[alert.alert_id] = HighFrequencyBehavior(
            category="scan",
            family=nearest[2].family,
            signal="correlated_web_scan_session",
            include_target_in_key=False,
        )
    return resolved


def _stable_service(alert: NormalizedAlert) -> str:
    service = alert.service or "<NULL>"
    source_port = str(alert.attributes.get("source_port") or "")
    destination_port = str(alert.attributes.get("destination_port") or "")
    protocol = str(alert.attributes.get("protocol") or "unknown")
    if (
        source_port.isdigit()
        and destination_port.isdigit()
        and int(source_port) <= 1024
        and int(destination_port) >= 49152
    ):
        return f"{protocol}/{source_port}"
    return service


def _aggregation_service(
    alert: NormalizedAlert,
    behavior: HighFrequencyBehavior,
) -> str:
    if behavior.category == "scan" and behavior.family.startswith("web_scan:"):
        return "web/http"
    if behavior.category == "scan":
        protocol = str(alert.attributes.get("protocol") or "").strip().casefold()
        if protocol:
            return protocol
        service = _stable_service(alert)
        # A scan session is keyed by protocol/service, not destination port:
        # scanning multiple ports is precisely the repetition being collapsed.
        without_numeric_port = re.sub(r"[/:-]\d+$", "", service).strip()
        return without_numeric_port or "unknown"
    return _stable_service(alert)


def _destination_ports(alert: NormalizedAlert) -> tuple[str, ...]:
    values: list[str] = []
    for key in ("destination_port", "dest_port", "dst_port", "dport"):
        raw = alert.attributes.get(key)
        if isinstance(raw, (list, tuple)):
            values.extend(str(item) for item in raw if str(item).strip())
        elif raw not in (None, ""):
            values.append(str(raw))
    if not values and alert.service:
        match = re.search(r"[/:-](\d+)$", alert.service)
        if match is not None:
            values.append(match.group(1))
    return tuple(
        sorted(
            set(values),
            key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value),
        )
    )


def _resources(alert: NormalizedAlert) -> tuple[str, ...]:
    resources: list[str] = list(_dns_query_names(alert))
    for key in ("url", "request", "query", "command"):
        value = alert.attributes.get(key)
        if value not in (None, "") and not isinstance(value, (Mapping, list, tuple)):
            resources.append(str(value))
    payload = alert.attributes.get("payload_fields")
    if isinstance(payload, Mapping):
        values = payload.get("affected_values")
        if isinstance(values, (list, tuple)):
            resources.extend(str(value) for value in values if value not in (None, ""))
    return tuple(dict.fromkeys(resources))


def _count_bucket(count: int) -> str:
    if count < 2:
        return "0-1"
    if count < 10:
        return "2-9"
    if count < 100:
        return "10-99"
    if count < 1000:
        return "100-999"
    return "1000+"


def _duration_bucket(duration_seconds: float) -> str:
    if duration_seconds < 60:
        return "<1m"
    if duration_seconds < 300:
        return "1-5m"
    if duration_seconds < 3600:
        return "5-60m"
    return "60m+"


def _rate_bucket(member_count: int, duration_seconds: float) -> str:
    rate = member_count * 60.0 / max(duration_seconds, 1.0)
    if rate < 1:
        return "<1/min"
    if rate < 10:
        return "1-10/min"
    if rate < 100:
        return "10-100/min"
    return "100+/min"


@dataclass(slots=True)
class SessionHighFrequencyAlertAggregator:
    """Collapse supported high-frequency sessions before HAT processing."""

    inactivity_threshold_seconds: int = 60
    minimum_members: int = 2
    maximum_session_duration_seconds: int = 900

    def __post_init__(self) -> None:
        if self.inactivity_threshold_seconds <= 0:
            raise ValueError("inactivity_threshold_seconds must be positive")
        if self.maximum_session_duration_seconds <= 0:
            raise ValueError("maximum_session_duration_seconds must be positive")
        if self.minimum_members < 2:
            raise ValueError("minimum_members must be at least 2")

    def _key(
        self,
        alert: NormalizedAlert,
        behavior: HighFrequencyBehavior,
    ) -> tuple[str, ...]:
        target = (
            alert.target_entity or "<NULL>"
            if behavior.include_target_in_key
            else "<ANY>"
        )
        return (
            behavior.category,
            behavior.family,
            _event_source(alert),
            target,
            _aggregation_service(alert, behavior),
        )

    def _meta_alert(
        self,
        behavior: HighFrequencyBehavior,
        members: list[NormalizedAlert],
    ) -> tuple[AlertObject, ...]:
        ordered = sorted(members, key=lambda item: (item.timestamp, item.alert_id))
        if len(ordered) < self.minimum_members:
            return tuple(ordered)
        digest_builder = hashlib.sha256()
        for member in ordered:
            digest_builder.update(member.alert_id.encode("utf-8"))
            digest_builder.update(b"\n")
        member_ids = tuple(item.alert_id for item in ordered)
        sources = tuple(sorted({_event_source(item) for item in ordered} - {"<NULL>"}))
        targets = tuple(
            sorted({item.target_entity for item in ordered if item.target_entity})
        )
        services = tuple(
            sorted({_aggregation_service(item, behavior) for item in ordered})
        )
        alert_sources = tuple(sorted({item.alert_source for item in ordered}))
        semantics = tuple(sorted({item.alert_semantics for item in ordered}))
        resources = {resource for item in ordered for resource in _resources(item)}
        destination_ports = {
            port for item in ordered for port in _destination_ports(item)
        }
        first_seen = ordered[0].timestamp
        last_seen = ordered[-1].timestamp
        duration = (last_seen - first_seen).total_seconds()
        prefix = behavior.category.replace("_", "-")
        statistics: dict[str, object] = {
            "aggregation_stage": 1,
            "behavior_category": behavior.category,
            "behavior_family": behavior.family,
            "detection_signal": behavior.signal,
            "member_count": len(ordered),
            "member_count_bucket": _count_bucket(len(ordered)),
            "duration_seconds": duration,
            "duration_bucket": _duration_bucket(duration),
            "event_rate_bucket": _rate_bucket(len(ordered), duration),
            "distinct_source_count": len(sources),
            "distinct_source_count_bucket": _count_bucket(len(sources)),
            "distinct_target_count": len(targets),
            "distinct_target_count_bucket": _count_bucket(len(targets)),
            "distinct_service_count": len(services),
            "distinct_service_count_bucket": _count_bucket(len(services)),
            "destination_ports": tuple(
                sorted(
                    destination_ports,
                    key=lambda value: (
                        not value.isdigit(),
                        int(value) if value.isdigit() else value,
                    ),
                )
            ),
            "distinct_destination_port_count": len(destination_ports),
            "distinct_destination_port_count_bucket": _count_bucket(
                len(destination_ports)
            ),
            "distinct_resource_count": len(resources),
            "distinct_resource_count_bucket": _count_bucket(len(resources)),
            "member_alert_sources": alert_sources,
            "member_alert_semantics": semantics,
            "normalized_behavior_template": {
                "category": behavior.category,
                "family": behavior.family,
                "service": services,
            },
        }
        if behavior.category == "scan":
            statistics["scan_family"] = behavior.family
        return (
            MetaAlert(
                meta_alert_id=(f"m1-{prefix}-{digest_builder.hexdigest()[:24]}"),
                member_alert_ids=member_ids,
                first_seen=first_seen,
                last_seen=last_seen,
                alert_source=(alert_sources[0] if len(alert_sources) == 1 else "mixed"),
                alert_semantics=f"{behavior.category}:{behavior.family}",
                source_entities=sources,
                target_entities=targets,
                services=services,
                statistics=statistics,
            ),
        )

    def _active_dns_tunnel_continuation(
        self,
        alert: NormalizedAlert,
        active: Mapping[
            tuple[str, ...],
            tuple[HighFrequencyBehavior, list[NormalizedAlert], datetime],
        ],
    ) -> (
        tuple[
            tuple[str, ...],
            tuple[HighFrequencyBehavior, list[NormalizedAlert], datetime],
        ]
        | None
    ):
        """Attach short DNS control fragments to a detected tunnel session."""

        if not _is_dns_context(alert) or not _dns_query_names(alert):
            return None
        source = _event_source(alert)
        target = alert.target_entity or "<NULL>"
        service = _stable_service(alert)
        base_domains = {_dns_base_domain(name) for name in _dns_query_names(alert)}
        candidates = [
            (key, current)
            for key, current in active.items()
            if current[0].category == "dns_tunnel"
            and key[2:] == (source, target, service)
            and (
                current[0].family == "explicit_tunnel"
                or current[0].family.removeprefix("encoded_subdomain:") in base_domains
            )
            and (alert.timestamp - current[2]).total_seconds()
            <= self.inactivity_threshold_seconds
            and (alert.timestamp - current[1][0].timestamp).total_seconds()
            <= self.maximum_session_duration_seconds
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[1][2])

    def aggregate(
        self,
        alerts: Iterable[NormalizedAlert],
    ) -> Stage1AggregationResult:
        batch = tuple(alerts)
        originals = {alert.alert_id: alert for alert in batch}
        if len(originals) != len(batch):
            raise ValueError("normalized alerts contain duplicate alert IDs")
        ordered = sorted(batch, key=lambda item: (item.timestamp, item.alert_id))
        direct_behaviors = {
            alert.alert_id: high_frequency_behavior(alert) for alert in ordered
        }
        resolved_behaviors = _correlate_web_scan_behaviors(
            tuple(ordered),
            direct_behaviors,
            self.inactivity_threshold_seconds,
        )
        active: dict[
            tuple[str, ...],
            tuple[HighFrequencyBehavior, list[NormalizedAlert], datetime],
        ] = {}
        output: list[AlertObject] = []
        for alert in ordered:
            behavior = resolved_behaviors[alert.alert_id]
            if behavior is None:
                continuation = self._active_dns_tunnel_continuation(
                    alert,
                    active,
                )
                if continuation is not None:
                    key, (current_behavior, members, _) = continuation
                    members.append(alert)
                    active[key] = (current_behavior, members, alert.timestamp)
                    continue
                output.append(alert)
                continue
            key = self._key(alert, behavior)
            current = active.get(key)
            if current is None:
                active[key] = (behavior, [alert], alert.timestamp)
                continue
            current_behavior, members, last_seen = current
            gap = (alert.timestamp - last_seen).total_seconds()
            session_duration = (alert.timestamp - members[0].timestamp).total_seconds()
            if (
                gap <= self.inactivity_threshold_seconds
                and session_duration <= self.maximum_session_duration_seconds
            ):
                members.append(alert)
                active[key] = (current_behavior, members, alert.timestamp)
                continue
            output.extend(self._meta_alert(current_behavior, members))
            active[key] = (behavior, [alert], alert.timestamp)
        for behavior, members, _ in active.values():
            output.extend(self._meta_alert(behavior, members))
        output.sort(
            key=lambda item: (
                item.timestamp
                if isinstance(item, NormalizedAlert)
                else item.first_seen,
                item.alert_id
                if isinstance(item, NormalizedAlert)
                else item.meta_alert_id,
            )
        )
        member_mapping: dict[str, str] = {}
        for item in output:
            if isinstance(item, MetaAlert):
                for member_id in item.member_alert_ids:
                    member_mapping[member_id] = item.meta_alert_id
            else:
                member_mapping[item.alert_id] = item.alert_id
        return Stage1AggregationResult(
            alerts=tuple(output),
            original_alerts_by_id=originals,
            member_to_aggregate=member_mapping,
        )


@dataclass(frozen=True, slots=True)
class EntityRuleWindowAlertAggregator:
    """Aggregate every repeated ``(source, target, semantics)`` in a time window.

    This dataset-oriented strategy deliberately does not classify behavior as
    scan, brute force, tunneling, or denial of service.  A session is defined
    only by the normalized equivalents of Tianyan ``sip``, ``dip``, and
    ``rule_name``.  The window is measured from the first member, preventing a
    continuously active key from chaining an entire day into one meta-alert.
    """

    window_seconds: int = 60
    minimum_members: int = 2

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.minimum_members < 2:
            raise ValueError("minimum_members must be at least 2")

    @staticmethod
    def _key(alert: NormalizedAlert) -> tuple[str, str, str]:
        return (
            alert.source_entity or "<NULL>",
            alert.target_entity or "<NULL>",
            alert.alert_semantics,
        )

    def _meta_alert(
        self,
        members: list[NormalizedAlert],
    ) -> tuple[AlertObject, ...]:
        ordered = sorted(members, key=lambda item: (item.timestamp, item.alert_id))
        if len(ordered) < self.minimum_members:
            return tuple(ordered)
        digest_builder = hashlib.sha256()
        for member in ordered:
            digest_builder.update(member.alert_id.encode("utf-8"))
            digest_builder.update(b"\n")
        member_ids = tuple(item.alert_id for item in ordered)
        sources = tuple(
            sorted({item.source_entity for item in ordered if item.source_entity})
        )
        targets = tuple(
            sorted({item.target_entity for item in ordered if item.target_entity})
        )
        services = tuple(sorted({item.service for item in ordered if item.service}))
        alert_sources = tuple(sorted({item.alert_source for item in ordered}))
        semantics = tuple(sorted({item.alert_semantics for item in ordered}))
        resources = {resource for item in ordered for resource in _resources(item)}
        destination_ports = {
            port for item in ordered for port in _destination_ports(item)
        }
        first_seen = ordered[0].timestamp
        last_seen = ordered[-1].timestamp
        duration = (last_seen - first_seen).total_seconds()
        rule_semantics = semantics[0]
        statistics: dict[str, object] = {
            "aggregation_stage": 1,
            "behavior_category": "same_sip_dip_rule_window",
            "behavior_family": rule_semantics,
            "detection_signal": "same_source_target_semantics_within_window",
            "aggregation_window_seconds": self.window_seconds,
            "member_count": len(ordered),
            "member_count_bucket": _count_bucket(len(ordered)),
            "duration_seconds": duration,
            "duration_bucket": _duration_bucket(duration),
            "event_rate_bucket": _rate_bucket(len(ordered), duration),
            "distinct_source_count": len(sources),
            "distinct_source_count_bucket": _count_bucket(len(sources)),
            "distinct_target_count": len(targets),
            "distinct_target_count_bucket": _count_bucket(len(targets)),
            "distinct_service_count": len(services),
            "distinct_service_count_bucket": _count_bucket(len(services)),
            "destination_ports": tuple(
                sorted(
                    destination_ports,
                    key=lambda value: (
                        not value.isdigit(),
                        int(value) if value.isdigit() else value,
                    ),
                )
            ),
            "distinct_destination_port_count": len(destination_ports),
            "distinct_destination_port_count_bucket": _count_bucket(
                len(destination_ports)
            ),
            "distinct_resource_count": len(resources),
            "distinct_resource_count_bucket": _count_bucket(len(resources)),
            "member_alert_sources": alert_sources,
            "member_alert_semantics": semantics,
            "normalized_behavior_template": {
                "category": "same_sip_dip_rule_window",
                "rule_name": rule_semantics,
            },
        }
        return (
            MetaAlert(
                meta_alert_id=(
                    f"m1-entity-rule-{digest_builder.hexdigest()[:24]}"
                ),
                member_alert_ids=member_ids,
                first_seen=first_seen,
                last_seen=last_seen,
                alert_source=(
                    alert_sources[0] if len(alert_sources) == 1 else "mixed"
                ),
                alert_semantics=rule_semantics,
                source_entities=sources,
                target_entities=targets,
                services=services,
                statistics=statistics,
            ),
        )

    def aggregate(
        self,
        alerts: Iterable[NormalizedAlert],
    ) -> Stage1AggregationResult:
        batch = tuple(alerts)
        originals = {alert.alert_id: alert for alert in batch}
        if len(originals) != len(batch):
            raise ValueError("normalized alerts contain duplicate alert IDs")
        ordered = sorted(batch, key=lambda item: (item.timestamp, item.alert_id))
        active: dict[tuple[str, str, str], list[NormalizedAlert]] = {}
        output: list[AlertObject] = []
        for alert in ordered:
            key = self._key(alert)
            members = active.get(key)
            if members is None:
                active[key] = [alert]
                continue
            elapsed = (alert.timestamp - members[0].timestamp).total_seconds()
            if elapsed <= self.window_seconds:
                members.append(alert)
                continue
            output.extend(self._meta_alert(members))
            active[key] = [alert]
        for members in active.values():
            output.extend(self._meta_alert(members))
        output.sort(
            key=lambda item: (
                item.timestamp
                if isinstance(item, NormalizedAlert)
                else item.first_seen,
                item.alert_id
                if isinstance(item, NormalizedAlert)
                else item.meta_alert_id,
            )
        )
        member_mapping: dict[str, str] = {}
        for item in output:
            if isinstance(item, MetaAlert):
                for member_id in item.member_alert_ids:
                    member_mapping[member_id] = item.meta_alert_id
            else:
                member_mapping[item.alert_id] = item.alert_id
        return Stage1AggregationResult(
            alerts=tuple(output),
            original_alerts_by_id=originals,
            member_to_aggregate=member_mapping,
        )


# Backwards-compatible name: the implementation now aggregates every supported
# high-frequency behavior, not only scans.
SessionScanAlertAggregator = SessionHighFrequencyAlertAggregator
