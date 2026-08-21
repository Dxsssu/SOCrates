"""JSON serialization helpers for audit-friendly pipeline artifacts."""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping


def to_primitive(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_primitive(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [to_primitive(item) for item in value]
    return value


def write_jsonl(path: str | Path, values: Iterable[object]) -> None:
    destination = Path(path)
    with destination.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(
                json.dumps(
                    to_primitive(value),
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )


def write_json(path: str | Path, value: object) -> None:
    Path(path).write_text(
        json.dumps(to_primitive(value), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
