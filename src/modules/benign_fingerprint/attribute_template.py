"""Deterministic payload normalization and attribute-template extraction."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any, Mapping, Protocol, runtime_checkable
from urllib.parse import unquote_plus

from ...models import NormalizedAlert


EMPTY_ATTRIBUTE_TEMPLATE = ""

UUID_RE = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])"
)
IPV4_RE = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
)
IPV6_RE = re.compile(
    r"(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])"
)
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[a-z0-9.-]+\.[a-z]{2,}(?![\w.-])")
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
ISO_TIMESTAMP_RE = re.compile(
    r"(?i)\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-6]\d"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
APACHE_TIMESTAMP_RE = re.compile(
    r"(?i)(?<!\w)\d{1,2}/"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:"
    r"[0-2]\d:[0-5]\d:[0-6]\d\s+[+-]\d{4}(?!\w)"
)
RFC1123_TIMESTAMP_RE = re.compile(
    r"(?i)\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+"
    r"[0-2]\d:[0-5]\d:[0-6]\d\s+(?:GMT|UTC|[+-]\d{4})\b"
)
SYSLOG_TIMESTAMP_RE = re.compile(
    r"(?i)\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+[0-2]\d:[0-5]\d:[0-6]\d(?:\s+\d{4})?\b"
)
ISO_DATE_RE = re.compile(r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)")
UNIX_TIMESTAMP_RE = re.compile(
    r"(?<![\d.])1\d{9}(?:\.\d{1,9})?(?![\d.])|"
    r"(?<![\d.])1\d{12}(?![\d.])"
)
TIME_OF_DAY_RE = re.compile(
    r"(?<!\d)[0-2]\d:[0-5]\d:[0-6]\d(?:\.\d+)?(?!\d)"
)
PROCESS_ID_RE = re.compile(r"(?<=\[)\d+(?=\])")
SHA256_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
SHA1_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
MD5_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
LONG_HEX_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{16,}(?![0-9a-f])")
BASE64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])"
)
QUERY_VALUE_RE = re.compile(
    r"(?i)(?P<prefix>(?:[?&;]|\b)(?P<key>[a-z][\w.-]*)=)"
    r"(?P<value>[^&#;\s]+)"
)

TOKEN_KEY_MARKERS = ("token", "secret", "nonce", "session", "cookie", "authorization")
TIMESTAMP_KEY_MARKERS = (
    "timestamp",
    "datetime",
    "notbefore",
    "notafter",
    "eventtime",
)
TIMESTAMP_KEYS = {
    "time",
    "date",
    "event_time",
    "event_date",
    "created",
    "created_at",
    "updated",
    "updated_at",
    "expires",
    "expires_at",
    "expiry",
}
IDENTIFIER_KEYS = {
    "id",
    "uid",
    "pid",
    "uuid",
    "tx_id",
    "flow_id",
    "request_id",
    "session_id",
    "user_id",
}
NUMBER_KEY_MARKERS = ("length", "bytes_", "pkts_", "count")
PAYLOAD_ATTRIBUTE_KEYS = (
    "payload_fields",
    "payload",
    "request",
    "url",
    "command",
    "query",
    "raw_log_data",
    "affected_paths",
    "affected_values",
)


@runtime_checkable
class AttributeTemplateExtractor(Protocol):
    """Extract a canonical template from the security-relevant alert payload."""

    def extract(self, alert: NormalizedAlert) -> str:
        """Return a deterministic template for the HAT attribute layer."""
        ...


def _placeholder_for_key(key: str) -> str | None:
    normalized = key.casefold()
    if any(marker in normalized for marker in TOKEN_KEY_MARKERS):
        return "<TOKEN>"
    if (
        any(marker in normalized for marker in TIMESTAMP_KEY_MARKERS)
        or normalized in TIMESTAMP_KEYS
        or normalized.endswith(("_time", "_date"))
    ):
        return "<TIMESTAMP>"
    if normalized in IDENTIFIER_KEYS or normalized.endswith(("_uuid", "_uid")):
        return "<ID>"
    if any(marker in normalized for marker in NUMBER_KEY_MARKERS):
        return "<NUMBER>"
    return None


def _normalize_query_values(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        placeholder = _placeholder_for_key(match.group("key"))
        if placeholder is None:
            return match.group(0)
        return match.group("prefix") + placeholder

    return QUERY_VALUE_RE.sub(replace, text)


def normalize_payload_text(
    value: str,
    max_characters: int = 4096,
    numeric_min_digits: int | None = 6,
) -> str:
    """Normalize encoded dynamic values while retaining stable payload structure."""

    if numeric_min_digits is not None and numeric_min_digits < 1:
        raise ValueError("numeric_min_digits must be positive")

    text = unicodedata.normalize("NFKC", value[:max_characters])
    if re.search(r"%[0-9a-fA-F]{2}", text):
        text = unquote_plus(text)
    text = " ".join(text.split())
    text = _normalize_query_values(text)
    text = JWT_RE.sub("<JWT>", text)
    text = UUID_RE.sub("<UUID>", text)
    text = MAC_RE.sub("<MAC>", text)
    text = EMAIL_RE.sub("<EMAIL>", text)
    text = APACHE_TIMESTAMP_RE.sub("<TIMESTAMP>", text)
    text = RFC1123_TIMESTAMP_RE.sub("<TIMESTAMP>", text)
    text = ISO_TIMESTAMP_RE.sub("<TIMESTAMP>", text)
    text = SYSLOG_TIMESTAMP_RE.sub("<TIMESTAMP>", text)
    text = ISO_DATE_RE.sub("<TIMESTAMP>", text)
    text = UNIX_TIMESTAMP_RE.sub("<TIMESTAMP>", text)
    text = TIME_OF_DAY_RE.sub("<TIMESTAMP>", text)
    text = PROCESS_ID_RE.sub("<PID>", text)
    text = IPV4_RE.sub("<IPV4>", text)
    text = IPV6_RE.sub("<IPV6>", text)
    text = SHA256_RE.sub("<SHA256>", text)
    text = SHA1_RE.sub("<SHA1>", text)
    text = MD5_RE.sub("<MD5>", text)
    text = LONG_HEX_RE.sub("<HEX>", text)
    if numeric_min_digits is not None:
        text = re.sub(
            rf"(?<![\w.])\d{{{numeric_min_digits},}}(?![\w.])",
            "<NUMBER>",
            text,
        )
    text = BASE64_TOKEN_RE.sub(_replace_encoded_token, text)
    return text


def _replace_encoded_token(match: re.Match[str]) -> str:
    """Replace only high-confidence encoded tokens, not ordinary long paths."""

    candidate = match.group(0)
    categories = (
        any(character.islower() for character in candidate),
        any(character.isupper() for character in candidate),
        any(character.isdigit() for character in candidate),
    )
    has_padding = "=" in candidate
    return "<TOKEN>" if all(categories) or has_padding else candidate


def _normalize_value(
    value: Any,
    key: str | None,
    max_characters: int,
    numeric_min_digits: int | None,
) -> Any:
    placeholder = _placeholder_for_key(key) if key is not None else None
    if placeholder is not None and value not in (None, "", [], {}):
        return placeholder
    if isinstance(value, Mapping):
        return {
            str(child_key): _normalize_value(
                child_value,
                str(child_key),
                max_characters,
                numeric_min_digits,
            )
            for child_key, child_value in sorted(value.items(), key=lambda item: str(item[0]))
            if child_value not in (None, "", [], {})
        }
    if isinstance(value, (list, tuple)):
        return [
            _normalize_value(item, key, max_characters, numeric_min_digits)
            for item in value
        ]
    if isinstance(value, str):
        return normalize_payload_text(value, max_characters, numeric_min_digits)
    if isinstance(value, (int, float)) and key is not None:
        if _placeholder_for_key(key) == "<NUMBER>":
            return "<NUMBER>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return normalize_payload_text(str(value), max_characters, numeric_min_digits)


def _canonicalize_exact_value(value: Any, max_characters: int) -> Any:
    """Canonicalize structure while retaining every concrete payload value."""

    if isinstance(value, Mapping):
        return {
            str(child_key): _canonicalize_exact_value(child_value, max_characters)
            for child_key, child_value in sorted(
                value.items(),
                key=lambda item: str(item[0]),
            )
            if child_value not in (None, "", [], {})
        }
    if isinstance(value, (list, tuple)):
        return [
            _canonicalize_exact_value(item, max_characters) for item in value
        ]
    if isinstance(value, str):
        text = unicodedata.normalize("NFKC", value[:max_characters])
        return " ".join(text.split())
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = unicodedata.normalize("NFKC", str(value)[:max_characters])
    return " ".join(text.split())


class PayloadAttributeTemplateExtractor:
    """Create canonical JSON templates from detector-specific payload fields."""

    def __init__(
        self,
        *,
        max_value_characters: int = 4096,
        max_template_characters: int = 16384,
        numeric_min_digits: int | None = 6,
        generalize_dynamic_values: bool = True,
    ) -> None:
        if max_value_characters < 1 or max_template_characters < 1:
            raise ValueError("attribute-template size limits must be positive")
        self.max_value_characters = max_value_characters
        self.max_template_characters = max_template_characters
        if numeric_min_digits is not None and numeric_min_digits < 1:
            raise ValueError("numeric_min_digits must be positive")
        self.numeric_min_digits = numeric_min_digits
        self.generalize_dynamic_values = generalize_dynamic_values

    def _payload(self, alert: NormalizedAlert) -> object | None:
        attributes = alert.attributes
        if "payload_fields" in attributes:
            return attributes["payload_fields"]
        selected = {
            key: attributes[key]
            for key in PAYLOAD_ATTRIBUTE_KEYS
            if key in attributes and key != "payload_fields"
        }
        return selected or None

    def extract(self, alert: NormalizedAlert) -> str:
        payload = self._payload(alert)
        if payload in (None, "", [], {}):
            return EMPTY_ATTRIBUTE_TEMPLATE
        normalized = (
            _normalize_value(
                payload,
                None,
                self.max_value_characters,
                self.numeric_min_digits,
            )
            if self.generalize_dynamic_values
            else _canonicalize_exact_value(payload, self.max_value_characters)
        )
        template = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(template) <= self.max_template_characters:
            return template
        digest = hashlib.sha256(template.encode("utf-8")).hexdigest()
        prefix_size = max(1, self.max_template_characters - 128)
        return json.dumps(
            {
                "template_prefix": template[:prefix_size],
                "template_sha256": digest,
                "truncated": True,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
