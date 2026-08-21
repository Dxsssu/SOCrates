"""Branch-specific typed generalization for verified benign fingerprints."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .event_tree import AlertPath, LAYER_ORDER


PLACEHOLDER_RE = re.compile(
    r"<(?:UUID|IPV4|IPV6|MAC|EMAIL|JWT|TIMESTAMP|PID|SHA256|SHA1|MD5|HEX|NUMBER|TOKEN|ID)>"
)


@dataclass(frozen=True, slots=True)
class TypedConstraint:
    """Accepted type and observed shape for one generalized value position."""

    layer: str
    occurrence: int
    placeholder: str
    accepted_shapes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GeneralizationInference:
    """A learned partially generalized path and its auditable constraints."""

    path: AlertPath
    generalized_fields: tuple[str, ...]
    constraints: tuple[TypedConstraint, ...]


def _character_shape(value: str) -> str:
    classes = "".join(
        name
        for name, present in (
            ("l", any(char.islower() for char in value)),
            ("u", any(char.isupper() for char in value)),
            ("d", any(char.isdigit() for char in value)),
            ("p", any(not char.isalnum() for char in value)),
        )
        if present
    )
    return classes or "empty"


def value_shape(placeholder: str, value: str) -> str:
    """Return a stable, deliberately coarse shape signature."""

    kind = placeholder.strip("<>").casefold()
    if placeholder == "<TIMESTAMP>":
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", value):
            return "timestamp:iso"
        if re.fullmatch(r"\d{1,2}/[A-Za-z]{3}/\d{4}:.*", value):
            return "timestamp:apache"
        if re.fullmatch(r"1\d{9}(?:\.\d+)?|1\d{12}", value):
            return "timestamp:epoch"
        if re.fullmatch(r"\d{2}:\d{2}:\d{2}(?:\.\d+)?", value):
            return "timestamp:time"
        return "timestamp:other"
    if placeholder in {"<NUMBER>", "<PID>"}:
        return f"{kind}:digits"
    if placeholder in {"<TOKEN>", "<ID>"}:
        return f"{kind}:{_character_shape(value)}"
    return kind


def _placeholder_matches(placeholder: str, value: str) -> bool:
    if not value:
        return False
    if placeholder == "<UUID>":
        return re.fullmatch(
            r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        ) is not None
    if placeholder in {"<IPV4>", "<IPV6>"}:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address.version == (4 if placeholder == "<IPV4>" else 6)
    if placeholder == "<MAC>":
        return re.fullmatch(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value) is not None
    if placeholder == "<EMAIL>":
        return re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) is not None
    if placeholder == "<JWT>":
        return re.fullmatch(
            r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            value,
        ) is not None
    if placeholder in {"<NUMBER>", "<PID>"}:
        return value.isdigit()
    if placeholder in {"<SHA256>", "<SHA1>", "<MD5>", "<HEX>"}:
        lengths = {"<SHA256>": 64, "<SHA1>": 40, "<MD5>": 32}
        expected = lengths.get(placeholder)
        return (
            re.fullmatch(r"(?i)[0-9a-f]+", value) is not None
            and (expected is None or len(value) == expected)
        )
    if placeholder == "<TIMESTAMP>":
        return value_shape(placeholder, value).startswith("timestamp:")
    if placeholder in {"<TOKEN>", "<ID>"}:
        return not any(character.isspace() for character in value)
    return False


def _captures(pattern: str, concrete: str) -> tuple[tuple[str, str], ...] | None:
    placeholders = tuple(PLACEHOLDER_RE.finditer(pattern))
    if not placeholders:
        return () if pattern == concrete else None

    # Avoid building one regular expression with many ``.+?`` groups.  Long
    # Web requests containing repeated separators can make that expression
    # backtrack exponentially.  Deterministically consume the literal text
    # between placeholders instead.  Adjacent placeholders are inherently
    # ambiguous, so fail closed rather than inventing a split.
    prefix = pattern[: placeholders[0].start()]
    if not concrete.startswith(prefix):
        return None
    cursor = len(prefix)
    captures: list[tuple[str, str]] = []
    for index, placeholder in enumerate(placeholders):
        next_start = (
            placeholders[index + 1].start()
            if index + 1 < len(placeholders)
            else len(pattern)
        )
        literal = pattern[placeholder.end() : next_start]
        if not literal:
            if index + 1 < len(placeholders):
                return None
            captured = concrete[cursor:]
            cursor = len(concrete)
        else:
            boundary = concrete.find(literal, cursor)
            if boundary < 0:
                return None
            captured = concrete[cursor:boundary]
            cursor = boundary + len(literal)
        if not captured:
            return None
        captures.append((placeholder.group(0), captured))
    if cursor != len(concrete):
        return None
    return tuple(captures)


def _infer_text_pattern(
    layer: str,
    candidate: str,
    concrete_values: tuple[str, ...],
) -> tuple[str, tuple[TypedConstraint, ...]] | None:
    placeholder_matches = tuple(PLACEHOLDER_RE.finditer(candidate))
    if not placeholder_matches:
        return None
    captured = tuple(_captures(candidate, value) for value in concrete_values)
    if any(value is None for value in captured):
        return None
    captures = tuple(value for value in captured if value is not None)
    output: list[str] = []
    constraints: list[TypedConstraint] = []
    cursor = 0
    retained_occurrence = 0
    for index, placeholder_match in enumerate(placeholder_matches):
        output.append(candidate[cursor : placeholder_match.start()])
        placeholder = placeholder_match.group(0)
        values = tuple(items[index][1] for items in captures)
        if len(set(values)) == 1:
            output.append(values[0])
        else:
            if not all(_placeholder_matches(placeholder, value) for value in values):
                return None
            output.append(placeholder)
            constraints.append(
                TypedConstraint(
                    layer=layer,
                    occurrence=retained_occurrence,
                    placeholder=placeholder,
                    accepted_shapes=tuple(
                        sorted({value_shape(placeholder, value) for value in values})
                    ),
                )
            )
            retained_occurrence += 1
        cursor = placeholder_match.end()
    output.append(candidate[cursor:])
    return "".join(output), tuple(constraints)


def _same_json_value(values: tuple[Any, ...]) -> bool:
    first = values[0]
    return all(type(value) is type(first) and value == first for value in values[1:])


def _infer_json_node(
    layer: str,
    candidate: Any,
    concrete_values: tuple[Any, ...],
    next_occurrence: list[int],
) -> tuple[Any, tuple[TypedConstraint, ...]] | None:
    if _same_json_value(concrete_values):
        return concrete_values[0], ()
    if isinstance(candidate, Mapping):
        keys = set(candidate)
        if not all(isinstance(value, Mapping) and set(value) == keys for value in concrete_values):
            return None
        learned: dict[str, Any] = {}
        constraints: list[TypedConstraint] = []
        for key in sorted(keys, key=str):
            inferred = _infer_json_node(
                layer,
                candidate[key],
                tuple(value[key] for value in concrete_values),
                next_occurrence,
            )
            if inferred is None:
                return None
            learned[str(key)] = inferred[0]
            constraints.extend(inferred[1])
        return learned, tuple(constraints)
    if isinstance(candidate, list):
        if not all(
            isinstance(value, list) and len(value) == len(candidate)
            for value in concrete_values
        ):
            return None
        learned_items: list[Any] = []
        constraints: list[TypedConstraint] = []
        for index, candidate_item in enumerate(candidate):
            inferred = _infer_json_node(
                layer,
                candidate_item,
                tuple(value[index] for value in concrete_values),
                next_occurrence,
            )
            if inferred is None:
                return None
            learned_items.append(inferred[0])
            constraints.extend(inferred[1])
        return learned_items, tuple(constraints)
    if not isinstance(candidate, str):
        return None

    whole_placeholder = PLACEHOLDER_RE.fullmatch(candidate)
    if whole_placeholder is not None:
        if any(value is None or isinstance(value, (bool, Mapping, list)) for value in concrete_values):
            return None
        placeholder = whole_placeholder.group(0)
        values = tuple(str(value) for value in concrete_values)
        if not all(_placeholder_matches(placeholder, value) for value in values):
            return None
        occurrence = next_occurrence[0]
        next_occurrence[0] += 1
        return candidate, (
            TypedConstraint(
                layer=layer,
                occurrence=occurrence,
                placeholder=placeholder,
                accepted_shapes=tuple(
                    sorted({value_shape(placeholder, value) for value in values})
                ),
            ),
        )
    if not all(isinstance(value, str) for value in concrete_values):
        return None
    inferred_text = _infer_text_pattern(layer, candidate, concrete_values)
    if inferred_text is None:
        return None
    learned_text, local_constraints = inferred_text
    offset = next_occurrence[0]
    remapped = tuple(
        TypedConstraint(
            layer=constraint.layer,
            occurrence=constraint.occurrence + offset,
            placeholder=constraint.placeholder,
            accepted_shapes=constraint.accepted_shapes,
        )
        for constraint in local_constraints
    )
    next_occurrence[0] += len(local_constraints)
    return learned_text, remapped


def _infer_attribute_pattern(
    layer: str,
    candidate: str,
    concrete_values: tuple[str, ...],
) -> tuple[str, tuple[TypedConstraint, ...]] | None:
    try:
        candidate_json = json.loads(candidate)
        concrete_json = tuple(json.loads(value) for value in concrete_values)
    except json.JSONDecodeError:
        return None
    inferred = _infer_json_node(layer, candidate_json, concrete_json, [0])
    if inferred is None or not inferred[1]:
        return None
    return (
        json.dumps(
            inferred[0],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        inferred[1],
    )


def _cidr_contains(pattern: str, values: tuple[str, ...]) -> bool:
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        addresses = tuple(ipaddress.ip_address(value) for value in values)
    except ValueError:
        return False
    return bool(addresses) and all(
        address.version == network.version and address in network
        for address in addresses
    )


def infer_generalized_path(
    candidate: AlertPath,
    exact_paths: tuple[AlertPath, ...],
) -> GeneralizationInference | None:
    """Infer only fields proven variable by multiple distinct exact paths."""

    if len({path.values for path in exact_paths}) < 2:
        return None
    learned_values: list[str] = []
    generalized_fields: list[str] = []
    constraints: list[TypedConstraint] = []
    for layer, candidate_value, exact_values_for_layer in zip(
        LAYER_ORDER,
        candidate.values,
        zip(*(path.values for path in exact_paths), strict=True),
        strict=True,
    ):
        exact_values = tuple(dict.fromkeys(exact_values_for_layer))
        if len(exact_values) == 1:
            learned_values.append(exact_values[0])
            continue
        inferred = (
            _infer_attribute_pattern(layer.value, candidate_value, exact_values)
            if layer.value == "attribute_template"
            else None
        )
        if inferred is None:
            inferred = _infer_text_pattern(layer.value, candidate_value, exact_values)
        if inferred is not None:
            learned_value, learned_constraints = inferred
            if learned_constraints:
                learned_values.append(learned_value)
                generalized_fields.append(layer.value)
                constraints.extend(learned_constraints)
                continue
        if layer.value in {"source_entity", "target_entity"} and _cidr_contains(
            candidate_value,
            exact_values,
        ):
            learned_values.append(candidate_value)
            generalized_fields.append(layer.value)
            continue
        return None
    if not generalized_fields:
        return None
    return GeneralizationInference(
        path=AlertPath(*learned_values),
        generalized_fields=tuple(generalized_fields),
        constraints=tuple(constraints),
    )


def _json_node_captures(
    pattern: Any,
    concrete: Any,
) -> tuple[tuple[str, str], ...] | None:
    if isinstance(pattern, Mapping):
        if not isinstance(concrete, Mapping) or set(concrete) != set(pattern):
            return None
        captures: list[tuple[str, str]] = []
        for key in sorted(pattern, key=str):
            nested = _json_node_captures(pattern[key], concrete[key])
            if nested is None:
                return None
            captures.extend(nested)
        return tuple(captures)
    if isinstance(pattern, list):
        if not isinstance(concrete, list) or len(concrete) != len(pattern):
            return None
        captures: list[tuple[str, str]] = []
        for pattern_item, concrete_item in zip(pattern, concrete, strict=True):
            nested = _json_node_captures(pattern_item, concrete_item)
            if nested is None:
                return None
            captures.extend(nested)
        return tuple(captures)
    if isinstance(pattern, str):
        whole_placeholder = PLACEHOLDER_RE.fullmatch(pattern)
        if whole_placeholder is not None:
            if concrete is None or isinstance(concrete, (bool, Mapping, list)):
                return None
            return ((whole_placeholder.group(0), str(concrete)),)
        if isinstance(concrete, str):
            return _captures(pattern, concrete)
        return None
    return () if type(pattern) is type(concrete) and pattern == concrete else None


def _attribute_captures(
    pattern: str,
    concrete: str,
) -> tuple[tuple[str, str], ...] | None:
    try:
        return _json_node_captures(json.loads(pattern), json.loads(concrete))
    except json.JSONDecodeError:
        return _captures(pattern, concrete)


def _matches_layer(
    layer: str,
    pattern: str,
    concrete: str,
    constraints: tuple[TypedConstraint, ...],
) -> bool:
    if pattern == concrete:
        return True
    if layer in {"source_entity", "target_entity"}:
        return _cidr_contains(pattern, (concrete,))
    captures = (
        _attribute_captures(pattern, concrete)
        if layer == "attribute_template"
        else _captures(pattern, concrete)
    )
    if captures is None:
        return False
    expected = {
        (constraint.occurrence, constraint.placeholder): constraint
        for constraint in constraints
        if constraint.layer == layer
    }
    for occurrence, (placeholder, value) in enumerate(captures):
        constraint = expected.get((occurrence, placeholder))
        if constraint is None or not _placeholder_matches(placeholder, value):
            return False
        if value_shape(placeholder, value) not in constraint.accepted_shapes:
            return False
    return len(captures) == len(expected)


def matches_generalized_path(
    pattern: AlertPath,
    concrete: AlertPath,
    constraints: tuple[TypedConstraint, ...],
) -> bool:
    """Match an exact path against all literal, subnet, type, and shape constraints."""

    return all(
        _matches_layer(layer.value, pattern_value, concrete_value, constraints)
        for layer, pattern_value, concrete_value in zip(
            LAYER_ORDER,
            pattern.values,
            concrete.values,
            strict=True,
        )
    )


def pattern_specificity(path: AlertPath) -> int:
    """Return a deterministic literal-character specificity score."""

    return sum(len(PLACEHOLDER_RE.sub("", value)) for value in path.values)
