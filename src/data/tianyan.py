"""Streaming helpers for the Tianyan alert export format.

The supplied Tianyan files are large, pretty-printed JSON arrays.  This module
deliberately parses one array item at a time so callers do not need to load a
multi-gigabyte daily file into memory.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Mapping
from zoneinfo import ZoneInfo

from ..models import NormalizedAlert, TianyanRecord


NETWORK_IDS_LOG_TYPE = "webids-ids_dolog"
WEB_IDS_LOG_TYPE = "webids-webattack_dolog"
TIANYAN_LOG_TYPE_TO_CATEGORY = {
    NETWORK_IDS_LOG_TYPE: "network_ids",
    WEB_IDS_LOG_TYPE: "web_ids",
}
TIANYAN_NORMALIZATION_VERSION = 2

_BRUTE_FORCE_MARKERS = (
    "暴力猜解",
    "暴力破解",
    "账号爆破",
    "账户爆破",
    "口令爆破",
    "密码爆破",
    "口令猜解",
    "密码猜解",
    "弱口令",
)
_SCAN_MARKERS = ("扫描", "端口探测", "主机探测", "目录枚举", "服务探测")
_DNS_TUNNEL_MARKERS = ("dns隧道", "dns 隧道", "域名隧道")
_DENIAL_OF_SERVICE_MARKERS = (
    "拒绝服务",
    "ddos",
    "dos攻击",
    "dos 攻击",
    "syn洪泛",
    "syn 洪泛",
    "请求洪泛",
    "连接洪泛",
)


class TianyanFormatError(ValueError):
    """Raised when a Tianyan input is not a valid JSON array of objects."""


def _as_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bounded_text(value: object | None, maximum: int = 4096) -> str | None:
    text = _as_text(value)
    return text[:maximum] if text is not None else None


def _without_empty(values: Mapping[str, object | None]) -> dict[str, object]:
    return {
        key: value
        for key, value in values.items()
        if value not in (None, "", [], {})
    }


def _truth_label(value: object) -> bool:
    if value is True or value == 1 or value == "1":
        return True
    if value is False or value == 0 or value == "0":
        return False
    raise ValueError(f"Tianyan is_attack must be 0 or 1, got {value!r}")


def _parse_timestamp(value: object, timezone_name: str) -> datetime:
    text = str(value).strip()
    if not text:
        raise ValueError("Tianyan alert has an empty @timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid Tianyan @timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name))
    return parsed


def _stable_alert_id(
    raw: Mapping[str, object],
    source_file: str,
    source_line: int,
    category: str,
) -> str:
    raw_uuid = _as_text(raw.get("uuid"))
    # Tianyan UUID values repeat across exported rows, so UUID alone is not a
    # valid alert identity.  File and line retain deterministic row identity;
    # the original UUID is included as additional provenance when available.
    material = f"{source_file}:{source_line}:{category}:{raw_uuid or ''}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
    return f"tianyan-{category}-{digest}"


def _behavior_hint(raw: Mapping[str, object]) -> str | None:
    """Map Chinese detector semantics to the existing label-free aggregator."""

    evidence = " ".join(
        text
        for value in (
            raw.get("rule_name"),
            raw.get("attack_type"),
            raw.get("vuln_type"),
            raw.get("detail_info"),
        )
        if (text := _as_text(value)) is not None
    ).casefold()
    if any(marker in evidence for marker in _BRUTE_FORCE_MARKERS):
        return "brute force password guessing"
    if any(marker in evidence for marker in _DNS_TUNNEL_MARKERS):
        return "dns tunnel"
    if any(marker in evidence for marker in _DENIAL_OF_SERVICE_MARKERS):
        return "denial of service"
    if any(marker in evidence for marker in _SCAN_MARKERS):
        return "scan"
    return None


def _payload_fields(
    raw: Mapping[str, object],
    category: str,
) -> dict[str, object]:
    """Select stable, rule-relevant fields for the HAT attribute layer.

    Network packet hex dumps contain volatile link/IP headers and would make
    exact fingerprints both fragile and very large, so the Network IDS HAT
    uses stable detector/protocol attributes.  Web IDS retains bounded request
    evidence but deliberately omits volatile response bodies and headers.
    """

    if category == "network_ids":
        return _without_empty(
            {
                "attack_type": _bounded_text(raw.get("attack_type"), 512),
                "vuln_type": _bounded_text(raw.get("vuln_type"), 512),
                "attack_method": _bounded_text(raw.get("attack_method"), 512),
                "appid": raw.get("appid"),
                "packet_size": raw.get("packet_size"),
            }
        )
    return _without_empty(
        {
            "method": _bounded_text(raw.get("method"), 32),
            "host": _bounded_text(raw.get("host"), 1024),
            "uri": _bounded_text(raw.get("uri")),
            "parameter": _bounded_text(raw.get("parameter")),
            "request_body": _bounded_text(raw.get("req_body")),
            "response_status": raw.get("rsp_status"),
            "content_type": _bounded_text(raw.get("rsp_content_type"), 512),
        }
    )


def normalize_tianyan_record(
    raw: Mapping[str, object],
    *,
    source_file: str,
    source_line: int,
    timezone_name: str = "Asia/Shanghai",
    raw_reference: str | None = None,
) -> TianyanRecord:
    """Normalize one extracted Tianyan IDS record without leaking truth.

    ``is_attack`` is returned only on :class:`TianyanRecord`; it is never
    copied into ``NormalizedAlert.attributes`` or any HAT feature.
    """

    raw_log_type = _as_text(raw.get("log_type"))
    category = TIANYAN_LOG_TYPE_TO_CATEGORY.get(raw_log_type or "")
    if category is None:
        raise ValueError(f"unsupported Tianyan log_type: {raw_log_type!r}")
    if "is_attack" not in raw:
        raise ValueError("Tianyan evaluation record has no is_attack label")
    timestamp_value = raw.get("@timestamp")
    if timestamp_value in (None, ""):
        raise ValueError("Tianyan alert has no @timestamp")

    protocol = _as_text(raw.get("proto"))
    destination_port = _as_text(raw.get("dport"))
    service = (
        f"{protocol or 'unknown'}/{destination_port}"
        if destination_port is not None
        else protocol
    )
    semantics = (
        _as_text(raw.get("rule_name"))
        or _as_text(raw.get("attack_type"))
        or "unknown Tianyan alert"
    )
    payload_fields = _payload_fields(raw, category)
    attributes = _without_empty(
        {
            "rule_id": _as_text(raw.get("rule_id")),
            "severity": raw.get("severity"),
            "confidence": raw.get("confidence"),
            "protocol": protocol,
            "source_port": _as_text(raw.get("sport")),
            "destination_port": destination_port,
            "attack_type": _as_text(raw.get("attack_type")),
            "vuln_type": _as_text(raw.get("vuln_type")),
            "attack_method": _as_text(raw.get("attack_method")),
            "behavior_hint": _behavior_hint(raw),
            "payload_fields": payload_fields,
        }
    )
    reference = raw_reference or f"{source_file}:{source_line}"
    alert = NormalizedAlert(
        alert_id=_stable_alert_id(raw, source_file, source_line, category),
        timestamp=_parse_timestamp(timestamp_value, timezone_name),
        alert_source=f"tianyan_{category}",
        alert_semantics=semantics,
        source_entity=_as_text(raw.get("sip")),
        target_entity=_as_text(raw.get("dip")),
        service=service,
        attributes=attributes,
        raw_reference=reference,
    )
    return TianyanRecord(
        alert=alert,
        is_attack=_truth_label(raw["is_attack"]),
        source_file=source_file,
        source_line=source_line,
        detector_source=category,
    )


def iter_tianyan_jsonl_file(
    path: str | Path,
    *,
    timezone_name: str = "Asia/Shanghai",
) -> Iterator[TianyanRecord]:
    """Stream normalized alerts from one extracted Tianyan JSONL file."""

    source = Path(path)
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TianyanFormatError(
                    f"invalid JSON at {source}:{line_number}: {exc}"
                ) from exc
            if not isinstance(value, Mapping):
                raise TianyanFormatError(
                    f"expected a JSON object at {source}:{line_number}"
                )
            yield normalize_tianyan_record(
                value,
                source_file=source.name,
                source_line=line_number,
                timezone_name=timezone_name,
                raw_reference=f"{source}:{line_number}",
            )


def iter_tianyan_raw_file(
    path: str | Path,
    *,
    chunk_size: int = 1024 * 1024,
    max_record_characters: int = 128 * 1024 * 1024,
    progress: Callable[[int], None] | None = None,
) -> Iterator[Mapping[str, object]]:
    """Yield objects from one Tianyan JSON array with bounded memory.

    ``progress`` receives the cumulative number of compressed-independent raw
    bytes read from the source file.  A generous per-record guard prevents one
    malformed file from growing the parser buffer without bound.
    """

    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    if max_record_characters < 1:
        raise ValueError("max_record_characters must be positive")

    source = Path(path)
    json_decoder = json.JSONDecoder()
    utf8_decoder = codecs.getincrementaldecoder("utf-8")()
    buffer = ""
    cursor = 0
    eof = False

    with source.open("rb") as handle:

        def fill() -> bool:
            nonlocal buffer, cursor, eof
            if cursor:
                buffer = buffer[cursor:]
                cursor = 0
            raw = handle.read(chunk_size)
            if raw:
                buffer += utf8_decoder.decode(raw)
                if progress is not None:
                    progress(handle.tell())
                return True
            if not eof:
                buffer += utf8_decoder.decode(b"", final=True)
                eof = True
                if progress is not None:
                    progress(handle.tell())
            return False

        def ensure_data() -> bool:
            while cursor >= len(buffer) and not eof:
                fill()
            return cursor < len(buffer)

        def skip_whitespace() -> bool:
            nonlocal cursor
            while True:
                while cursor < len(buffer) and buffer[cursor].isspace():
                    cursor += 1
                if cursor < len(buffer):
                    return True
                if eof:
                    return False
                fill()

        fill()
        if not skip_whitespace() or buffer[cursor] != "[":
            raise TianyanFormatError(f"expected a top-level JSON array: {source}")
        cursor += 1
        first = True

        while True:
            if not skip_whitespace():
                raise TianyanFormatError(f"unterminated JSON array: {source}")

            if buffer[cursor] == "]":
                cursor += 1
                break
            if not first:
                if buffer[cursor] != ",":
                    raise TianyanFormatError(
                        f"expected ',' between array items in {source}"
                    )
                cursor += 1
                if not skip_whitespace():
                    raise TianyanFormatError(f"unterminated JSON array: {source}")
            first = False

            while True:
                value_start = cursor
                try:
                    value, end = json_decoder.raw_decode(buffer, cursor)
                except json.JSONDecodeError as exc:
                    if eof:
                        raise TianyanFormatError(
                            f"invalid JSON array item in {source}: {exc}"
                        ) from exc
                    cursor = value_start
                    fill()
                    if len(buffer) > max_record_characters:
                        raise TianyanFormatError(
                            f"one JSON item exceeds {max_record_characters:,} "
                            f"characters in {source}"
                        ) from exc
                    continue
                cursor = end
                break

            if not isinstance(value, Mapping):
                raise TianyanFormatError(
                    f"expected every Tianyan array item to be an object: {source}"
                )
            yield value

        while True:
            while cursor < len(buffer) and buffer[cursor].isspace():
                cursor += 1
            if cursor < len(buffer):
                raise TianyanFormatError(
                    f"unexpected content after the top-level array: {source}"
                )
            if eof:
                return
            fill()


def extract_tianyan_ids_file(
    source_path: str | Path,
    *,
    output_path: str | Path,
    max_records: int | None = None,
    progress: Callable[[int], None] | None = None,
) -> dict[str, object]:
    """Extract Network IDS and Web IDS records from one daily Tianyan file.

    The two selected log types are written together as compact UTF-8 JSONL.
    The output is replaced atomically only after the source file has been
    processed successfully.  All original record fields and values, including
    evaluation fields, are preserved; only JSON whitespace formatting changes.
    """

    if max_records is not None and max_records < 1:
        raise ValueError("max_records must be positive")

    source = Path(source_path)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.part")

    log_type_counts: Counter[str] = Counter()
    selected_counts: Counter[str] = Counter()
    records_seen = 0
    completed_input = True
    with temporary.open("w", encoding="utf-8", newline="\n") as writer:
        for record in iter_tianyan_raw_file(source, progress=progress):
            records_seen += 1
            raw_log_type = record.get("log_type")
            log_type = (
                str(raw_log_type).strip()
                if raw_log_type not in (None, "")
                else "<missing>"
            )
            log_type_counts[log_type] += 1
            category = TIANYAN_LOG_TYPE_TO_CATEGORY.get(log_type)
            if category is not None:
                writer.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                selected_counts[category] += 1
            if max_records is not None and records_seen >= max_records:
                completed_input = False
                break
        writer.flush()
        os.fsync(writer.fileno())

    os.replace(temporary, output)

    return {
        "source_file": source.name,
        "source_path": str(source.resolve()),
        "source_bytes": source.stat().st_size,
        "source_mtime_ns": source.stat().st_mtime_ns,
        "records_seen": records_seen,
        "complete_input": completed_input,
        "log_type_counts": dict(sorted(log_type_counts.items())),
        "selected_counts": {
            category: selected_counts[category]
            for category in ("network_ids", "web_ids")
        },
        "output": {
            "path": str(output.resolve()),
            "bytes": output.stat().st_size,
        },
    }
