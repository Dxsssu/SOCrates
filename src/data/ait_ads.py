"""Streaming normalization adapters for labeled or unlabeled AIT-ADS JSONL."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from ..models import AITADSRecord, NormalizedAlert


LABEL_FIELDS = {
    "label",
    "event_label",
    "time_label",
    "triage_label",
    "has_attack_event_label",
}


def _first(mapping: Mapping, *paths: tuple[str, ...]) -> object | None:
    for path in paths:
        current: object = mapping
        for part in path:
            if not isinstance(current, Mapping) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, "", []):
            return current
    return None


def _as_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_iso_timestamp(value: object) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp is missing a timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _stable_alert_id(source_file: str, source_line: int, detector: str) -> str:
    material = f"{source_file}:{source_line}:{detector}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"ait-{detector}-{digest}"


def _without_none(mapping: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in mapping.items()
        if value is not None and key.casefold() not in LABEL_FIELDS
    }


def _normalize_wazuh(
    raw: Mapping,
    source_file: str,
    source_line: int,
    raw_reference: str,
) -> AITADSRecord:
    location = _as_text(raw.get("location"))
    is_suricata = location == "/var/log/suricata/eve.json"
    detector = "suricata" if is_suricata else "wazuh"
    data = raw.get("data") if isinstance(raw.get("data"), Mapping) else {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), Mapping) else {}
    alert_data = data.get("alert") if isinstance(data.get("alert"), Mapping) else {}
    http = data.get("http") if isinstance(data.get("http"), Mapping) else {}
    decoder = raw.get("decoder") if isinstance(raw.get("decoder"), Mapping) else {}
    audit = data.get("audit") if isinstance(data.get("audit"), Mapping) else {}

    timestamp_value = _first(
        raw,
        ("@timestamp",),
        ("data", "timestamp"),
    )
    if timestamp_value is None:
        raise ValueError("Wazuh/Suricata record has no timestamp")
    timestamp = _parse_iso_timestamp(timestamp_value)
    semantics = _as_text(
        alert_data.get("signature") if is_suricata else rule.get("description")
    ) or _as_text(rule.get("description")) or "unknown alert"
    source = _as_text(_first(data, ("src_ip",), ("srcip",), ("src_ip_addr",)))
    target = _as_text(_first(data, ("dest_ip",), ("dstip",), ("dst_ip",)))
    if target is None:
        agent = raw.get("agent") if isinstance(raw.get("agent"), Mapping) else {}
        target = _as_text(agent.get("ip"))
    protocol = _as_text(_first(data, ("app_proto",), ("proto",), ("protocol",)))
    destination_port = _as_text(_first(data, ("dest_port",), ("dstport",)))
    service = protocol
    if destination_port:
        service = f"{protocol or 'unknown'}/{destination_port}"

    if is_suricata:
        # Native EVE alerts do not contain Wazuh full_log. Prefer structured
        # application-layer evidence and omit volatile flow/timestamp fields.
        payload_fields = _without_none(
            {
                "http": data.get("http"),
                "dns": data.get("dns"),
                "tls": data.get("tls"),
                "files": data.get("files"),
                "smtp": data.get("smtp"),
                "ssh": data.get("ssh"),
                "raw_payload": data.get("payload"),
                "packet": data.get("packet"),
            }
        )
    else:
        # For Wazuh, full_log is the primary rule-triggering payload. Retain
        # additional command, URL, user, and correlated-output evidence when
        # the decoder exposes it.
        payload_fields = _without_none(
            {
                "full_log": raw.get("full_log"),
                "previous_output": raw.get("previous_output"),
                "url": data.get("url"),
                "command": data.get("command") or audit.get("command"),
                "audit_executable": audit.get("exe"),
                "source_user": data.get("srcuser"),
                "target_user": data.get("dstuser"),
            }
        )

    attributes = _without_none(
        {
            "rule_id": _as_text(rule.get("id")),
            "severity": _first(alert_data, ("severity",)) or rule.get("level"),
            "rule_groups": rule.get("groups"),
            "location": location,
            "decoder": _as_text(decoder.get("name")),
            "protocol": protocol,
            "source_port": _as_text(_first(data, ("src_port",), ("srcport",))),
            "destination_port": destination_port,
            "signature_id": _as_text(alert_data.get("signature_id")),
            "alert_category": _as_text(alert_data.get("category")),
            "http_method": _as_text(http.get("http_method"))
            or _as_text(data.get("protocol")),
            "url": _as_text(http.get("url")) or _as_text(data.get("url")),
            "user_agent": _as_text(http.get("http_user_agent")),
            "payload": _as_text(raw.get("full_log")),
            "payload_fields": payload_fields,
        }
    )
    alert = NormalizedAlert(
        alert_id=_stable_alert_id(source_file, source_line, detector),
        timestamp=timestamp,
        alert_source=detector,
        alert_semantics=semantics,
        source_entity=source,
        target_entity=target,
        service=service,
        attributes=attributes,
        raw_reference=raw_reference,
    )
    return AITADSRecord(
        alert=alert,
        label=_as_text(raw.get("label")),
        source_file=source_file,
        source_line=source_line,
        detector_source=detector,
    )


def _normalize_aminer(
    raw: Mapping,
    source_file: str,
    source_line: int,
    raw_reference: str,
) -> AITADSRecord:
    log_data = raw.get("LogData") if isinstance(raw.get("LogData"), Mapping) else {}
    component = (
        raw.get("AnalysisComponent")
        if isinstance(raw.get("AnalysisComponent"), Mapping)
        else {}
    )
    aminer = raw.get("AMiner") if isinstance(raw.get("AMiner"), Mapping) else {}
    timestamps = log_data.get("Timestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise ValueError("AMiner record has no LogData.Timestamps[0]")
    timestamp = datetime.fromtimestamp(float(timestamps[0]), tz=timezone.utc)
    resources = log_data.get("LogResources")
    service = (
        _as_text(resources[0])
        if isinstance(resources, list) and resources
        else _as_text(component.get("AnalysisComponentType"))
    )
    raw_lines = log_data.get("RawLogData")
    raw_payload = raw_lines[0] if isinstance(raw_lines, list) and raw_lines else None
    target = _as_text(aminer.get("ID"))
    attributes = _without_none(
        {
            "component_type": _as_text(component.get("AnalysisComponentType")),
            "component_id": component.get("AnalysisComponentIdentifier"),
            "message": _as_text(component.get("Message")),
            "affected_paths": component.get("AffectedLogAtomPaths"),
            "affected_values": component.get("AffectedLogAtomValues"),
            "training_mode": component.get("TrainingMode"),
            "log_resource": service,
            "payload": _as_text(raw_payload),
            "payload_fields": _without_none(
                {
                    "raw_log_data": raw_lines,
                    "message": component.get("Message"),
                    "affected_paths": component.get("AffectedLogAtomPaths"),
                    "affected_values": component.get("AffectedLogAtomValues"),
                }
            ),
        }
    )
    alert = NormalizedAlert(
        alert_id=_stable_alert_id(source_file, source_line, "aminer"),
        timestamp=timestamp,
        alert_source="aminer",
        alert_semantics=(
            _as_text(component.get("AnalysisComponentName")) or "unknown AMiner alert"
        ),
        source_entity=None,
        target_entity=target,
        service=service,
        attributes=attributes,
        raw_reference=raw_reference,
    )
    return AITADSRecord(
        alert=alert,
        label=_as_text(raw.get("label")),
        source_file=source_file,
        source_line=source_line,
        detector_source="aminer",
    )


def normalize_ait_ads_record(
    raw: Mapping,
    *,
    source_file: str,
    source_line: int,
    raw_reference: str | None = None,
) -> AITADSRecord:
    """Normalize one raw AIT-ADS object without copying truth into the alert."""

    reference = raw_reference or f"{source_file}:{source_line}"
    if "AMiner" in raw and "LogData" in raw:
        return _normalize_aminer(raw, source_file, source_line, reference)
    return _normalize_wazuh(raw, source_file, source_line, reference)


def iter_ait_ads_file(path: str | Path) -> Iterator[AITADSRecord]:
    """Yield normalized records one line at a time from an AIT-ADS JSONL file."""

    source_path = Path(path)
    with source_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON at {source_path}:{line_number}: {exc}"
                ) from exc
            if not isinstance(value, Mapping):
                raise ValueError(
                    f"expected a JSON object at {source_path}:{line_number}"
                )
            yield normalize_ait_ads_record(
                value,
                source_file=source_path.name,
                source_line=line_number,
                raw_reference=f"{source_path}:{line_number}",
            )


def iter_ait_ads(paths: Iterable[str | Path]) -> Iterator[AITADSRecord]:
    """Stream one or more detector files without loading raw JSON into memory."""

    for path in paths:
        yield from iter_ait_ads_file(path)
