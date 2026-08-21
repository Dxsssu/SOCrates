"""Configuration contracts shared by the three SOCRates modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class BenignFingerprintConfig:
    """Settings for hierarchical benign fingerprint filtering."""

    minimum_support: int = 1
    generalized_minimum_support: int = 2
    generalized_minimum_distinct_paths: int = 2
    fingerprint_ttl_seconds: int | None = None
    require_verified_status: bool = True
    max_provenance_alert_ids: int | None = 1000
    entity_ipv4_prefix_length: int | None = 24
    entity_ipv6_prefix_length: int | None = 64
    attribute_numeric_min_digits: int | None = 3
    # SQLite is the preferred durable store. ``hat_state_path`` retains
    # backward compatibility with the earlier JSON snapshot implementation.
    hat_database_path: str | None = None
    hat_state_path: str | None = None
    high_frequency_preaggregation_enabled: bool = True
    high_frequency_inactivity_threshold_seconds: int = 60
    high_frequency_max_session_duration_seconds: int = 900
    high_frequency_min_members: int = 2
    high_frequency_always_forward_categories: tuple[str, ...] = (
        "brute_force",
        "dns_tunnel",
        "denial_of_service",
    )
    # Deprecated aliases retained for older configuration files and callers.
    # When supplied, they override the corresponding high-frequency setting.
    scan_preaggregation_enabled: bool | None = None
    scan_inactivity_threshold_seconds: int | None = None
    scan_min_members: int | None = None

    def __post_init__(self) -> None:
        if self.minimum_support < 1:
            raise ValueError("minimum_support must be at least 1")
        if self.generalized_minimum_support < 2:
            raise ValueError("generalized_minimum_support must be at least 2")
        if self.generalized_minimum_distinct_paths < 2:
            raise ValueError(
                "generalized_minimum_distinct_paths must be at least 2"
            )
        if (
            self.fingerprint_ttl_seconds is not None
            and self.fingerprint_ttl_seconds <= 0
        ):
            raise ValueError("fingerprint_ttl_seconds must be positive")
        if (
            self.max_provenance_alert_ids is not None
            and self.max_provenance_alert_ids < 1
        ):
            raise ValueError("max_provenance_alert_ids must be positive")
        if (
            self.entity_ipv4_prefix_length is not None
            and not 0 <= self.entity_ipv4_prefix_length <= 32
        ):
            raise ValueError("entity_ipv4_prefix_length must be in [0, 32]")
        if (
            self.entity_ipv6_prefix_length is not None
            and not 0 <= self.entity_ipv6_prefix_length <= 128
        ):
            raise ValueError("entity_ipv6_prefix_length must be in [0, 128]")
        if (
            self.attribute_numeric_min_digits is not None
            and self.attribute_numeric_min_digits < 1
        ):
            raise ValueError("attribute_numeric_min_digits must be positive")
        if self.hat_database_path is not None and not self.hat_database_path.strip():
            raise ValueError("hat_database_path cannot be blank")
        if self.hat_state_path is not None and not self.hat_state_path.strip():
            raise ValueError("hat_state_path cannot be blank")
        if self.hat_database_path is not None and self.hat_state_path is not None:
            raise ValueError(
                "configure only one of hat_database_path and hat_state_path"
            )
        if self.high_frequency_inactivity_threshold_seconds <= 0:
            raise ValueError(
                "high_frequency_inactivity_threshold_seconds must be positive"
            )
        if self.high_frequency_min_members < 2:
            raise ValueError("high_frequency_min_members must be at least 2")
        if self.high_frequency_max_session_duration_seconds <= 0:
            raise ValueError(
                "high_frequency_max_session_duration_seconds must be positive"
            )
        if any(
            not category.strip()
            for category in self.high_frequency_always_forward_categories
        ):
            raise ValueError(
                "high_frequency_always_forward_categories cannot contain blanks"
            )
        if (
            self.scan_inactivity_threshold_seconds is not None
            and self.scan_inactivity_threshold_seconds <= 0
        ):
            raise ValueError("scan_inactivity_threshold_seconds must be positive")
        if self.scan_min_members is not None and self.scan_min_members < 2:
            raise ValueError("scan_min_members must be at least 2")

    @property
    def preaggregation_enabled(self) -> bool:
        """Return the resolved module-one high-frequency aggregation switch."""

        if self.scan_preaggregation_enabled is not None:
            return self.scan_preaggregation_enabled
        return self.high_frequency_preaggregation_enabled

    @property
    def preaggregation_inactivity_threshold_seconds(self) -> int:
        """Return the resolved session inactivity threshold."""

        if self.scan_inactivity_threshold_seconds is not None:
            return self.scan_inactivity_threshold_seconds
        return self.high_frequency_inactivity_threshold_seconds

    @property
    def preaggregation_min_members(self) -> int:
        """Return the resolved minimum session size."""

        if self.scan_min_members is not None:
            return self.scan_min_members
        return self.high_frequency_min_members


@dataclass(frozen=True, slots=True)
class GraphPrioritizationConfig:
    """Settings for graph-based prioritization.

    ``inactivity_threshold_seconds`` remains accepted for configuration
    compatibility; burst aggregation now belongs exclusively to module one.
    """

    inactivity_threshold_seconds: int = 60
    graph_database_path: str | None = None
    candidate_threshold: float = 0.7
    # The paper computes frequencies on the current-day graph.  The reference
    # implementation uses UTC-anchored tumbling windows; ``None`` retains a
    # single caller-supplied batch for compatibility experiments.
    frequency_window_seconds: int | None = 86400
    pattern_numeric_min_digits: int | None = 3
    alert_weight: float = 1.0 / 3.0
    entity_weight: float = 1.0 / 3.0
    relation_weight: float = 1.0 / 3.0

    def __post_init__(self) -> None:
        if self.inactivity_threshold_seconds <= 0:
            raise ValueError("inactivity_threshold_seconds must be positive")
        if (
            self.graph_database_path is not None
            and not self.graph_database_path.strip()
        ):
            raise ValueError("graph_database_path cannot be blank")
        if not 0.0 <= self.candidate_threshold <= 1.0:
            raise ValueError("candidate_threshold must be in [0, 1]")
        if (
            self.frequency_window_seconds is not None
            and self.frequency_window_seconds <= 0
        ):
            raise ValueError("frequency_window_seconds must be positive")
        if (
            self.pattern_numeric_min_digits is not None
            and self.pattern_numeric_min_digits < 1
        ):
            raise ValueError("pattern_numeric_min_digits must be positive")
        weights = (self.alert_weight, self.entity_weight, self.relation_weight)
        if any(weight < 0.0 for weight in weights):
            raise ValueError("graph score weights cannot be negative")
        if abs(sum(weights) - 1.0) > 1e-9:
            raise ValueError("graph score weights must sum to 1")


@dataclass(frozen=True, slots=True)
class LLMInvestigationConfig:
    """Settings for knowledge retrieval and evidence-guided adjudication."""

    retrieval_top_k: int = 5
    retrieval_similarity_threshold: float = 0.7
    retrieval_semantic_alias_groups: tuple[tuple[str, ...], ...] = ()
    knowledge_database_path: str | None = None
    embedding_api_url: str = "https://open.bigmodel.cn/api/paas/v4/embeddings"
    embedding_model: str = "embedding-3"
    embedding_dimensions: int = 1024
    embedding_api_key_env: str = "SOCRATES_EMBEDDING_API_KEY"
    embedding_batch_size: int = 64
    embedding_timeout_seconds: float = 60.0
    embedding_max_retries: int = 2
    embedding_retry_backoff_seconds: float = 1.0
    embedding_max_input_characters: int = 12000
    backward_window_seconds: int = 1800
    forward_window_seconds: int = 1800
    max_context_items_per_direction: int = 5
    context_max_hops: int = 1
    # None means every module-two candidate is sent to module three.
    max_candidates_per_run: int | None = None
    api_url: str = "https://llmapi.paratera.com/v1/chat/completions"
    model: str = "DeepSeek-V4-Flash"
    api_key_env: str = "SOCRATES_LLM_API_KEY"
    request_timeout_seconds: float = 60.0
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    max_output_tokens: int = 800
    max_field_characters: int = 4096

    def __post_init__(self) -> None:
        normalized_alias_groups: list[tuple[str, ...]] = []
        semantic_groups: dict[str, int] = {}
        for group_index, raw_group in enumerate(
            self.retrieval_semantic_alias_groups
        ):
            if isinstance(raw_group, str):
                raise ValueError(
                    "each retrieval semantic alias group must be a sequence"
                )
            group = tuple(" ".join(str(item).split()) for item in raw_group)
            if len(group) < 2 or any(not item for item in group):
                raise ValueError(
                    "each retrieval semantic alias group must contain at least "
                    "two non-blank values"
                )
            normalized = tuple(item.casefold() for item in group)
            if len(normalized) != len(set(normalized)):
                raise ValueError(
                    "a retrieval semantic alias group cannot contain duplicates"
                )
            for semantic in normalized:
                if semantic in semantic_groups:
                    raise ValueError(
                        "a retrieval semantic alias cannot belong to multiple groups"
                    )
                semantic_groups[semantic] = group_index
            normalized_alias_groups.append(group)
        object.__setattr__(
            self,
            "retrieval_semantic_alias_groups",
            tuple(normalized_alias_groups),
        )
        if self.retrieval_top_k < 1:
            raise ValueError("retrieval_top_k must be at least 1")
        if not 0.0 <= self.retrieval_similarity_threshold <= 1.0:
            raise ValueError("retrieval_similarity_threshold must be in [0, 1]")
        if (
            self.knowledge_database_path is not None
            and not self.knowledge_database_path.strip()
        ):
            raise ValueError("knowledge_database_path cannot be blank")
        if not self.embedding_api_url.startswith(("http://", "https://")):
            raise ValueError("embedding_api_url must be an HTTP(S) URL")
        if not self.embedding_model.strip():
            raise ValueError("embedding_model cannot be empty")
        if self.embedding_dimensions < 1:
            raise ValueError("embedding_dimensions must be positive")
        if not self.embedding_api_key_env.strip():
            raise ValueError("embedding_api_key_env cannot be empty")
        if not 1 <= self.embedding_batch_size <= 64:
            raise ValueError("embedding_batch_size must be in [1, 64]")
        if self.embedding_timeout_seconds <= 0:
            raise ValueError("embedding_timeout_seconds must be positive")
        if self.embedding_max_retries < 0:
            raise ValueError("embedding_max_retries cannot be negative")
        if self.embedding_retry_backoff_seconds < 0:
            raise ValueError("embedding_retry_backoff_seconds cannot be negative")
        if self.embedding_max_input_characters < 1:
            raise ValueError("embedding_max_input_characters must be positive")
        if self.backward_window_seconds < 0 or self.forward_window_seconds < 0:
            raise ValueError("context windows cannot be negative")
        if self.max_context_items_per_direction < 1:
            raise ValueError("max_context_items_per_direction must be at least 1")
        if not 1 <= self.context_max_hops <= 8:
            raise ValueError("context_max_hops must be in [1, 8]")
        if self.max_candidates_per_run is not None and self.max_candidates_per_run < 1:
            raise ValueError("max_candidates_per_run must be at least 1")
        if not self.api_url.startswith(("http://", "https://")):
            raise ValueError("api_url must be an HTTP(S) URL")
        if not self.model.strip():
            raise ValueError("model cannot be empty")
        if not self.api_key_env.strip():
            raise ValueError("api_key_env cannot be empty")
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds cannot be negative")
        if self.max_output_tokens < 1 or self.max_field_characters < 1:
            raise ValueError("LLM output and field limits must be positive")


@dataclass(frozen=True, slots=True)
class AITADSConfig:
    """Initialization and evaluation protocol for one AIT-ADS scenario run."""

    input_paths: tuple[str, ...]
    output_directory: str
    hat_initialization_fraction: float = 0.20
    outside_attack_window_label: str = "benign"

    def __post_init__(self) -> None:
        if not self.input_paths:
            raise ValueError("AIT-ADS input_paths cannot be empty")
        if not self.output_directory.strip():
            raise ValueError("output_directory cannot be empty")
        if not 0.0 < self.hat_initialization_fraction <= 1.0:
            raise ValueError("hat_initialization_fraction must be in (0, 1]")
        if not self.outside_attack_window_label.strip():
            raise ValueError("outside_attack_window_label cannot be empty")


@dataclass(frozen=True, slots=True)
class SOCRatesConfig:
    """Top-level configuration for an end-to-end SOCRates pipeline."""

    benign_fingerprint: BenignFingerprintConfig = field(
        default_factory=BenignFingerprintConfig
    )
    graph_prioritization: GraphPrioritizationConfig = field(
        default_factory=GraphPrioritizationConfig
    )
    llm_investigation: LLMInvestigationConfig = field(
        default_factory=LLMInvestigationConfig
    )
    ait_ads: AITADSConfig | None = None

    def __post_init__(self) -> None:
        graph_path = self.graph_prioritization.graph_database_path
        hat_path = (
            self.benign_fingerprint.hat_database_path
            or self.benign_fingerprint.hat_state_path
        )
        knowledge_path = self.llm_investigation.knowledge_database_path
        named_paths = tuple(
            (name, Path(path).expanduser().resolve())
            for name, path in (
                ("HAT", hat_path),
                ("alert graph", graph_path),
                ("knowledge vector", knowledge_path),
            )
            if path is not None
        )
        for index, (left_name, left_path) in enumerate(named_paths):
            for right_name, right_path in named_paths[index + 1 :]:
                if left_path == right_path:
                    raise ValueError(
                        f"{left_name} and {right_name} databases must use different paths"
                    )


def _section(mapping: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = mapping.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"configuration section {name!r} must be a mapping")
    return value


def config_from_mapping(mapping: Mapping[str, Any]) -> SOCRatesConfig:
    """Build validated dataclass configuration from a YAML-style mapping."""

    benign_values = dict(_section(mapping, "benign_fingerprint"))
    protected_categories = benign_values.get("high_frequency_always_forward_categories")
    if protected_categories is not None:
        benign_values["high_frequency_always_forward_categories"] = tuple(
            str(item) for item in protected_categories
        )
    benign = BenignFingerprintConfig(**benign_values)
    graph = GraphPrioritizationConfig(**dict(_section(mapping, "graph_prioritization")))
    llm = LLMInvestigationConfig(**dict(_section(mapping, "llm_investigation")))
    data_mapping = _section(mapping, "ait_ads")
    data = None
    if data_mapping:
        data_values = dict(data_mapping)
        data_values["input_paths"] = tuple(
            str(item) for item in data_values["input_paths"]
        )
        data = AITADSConfig(**data_values)
    return SOCRatesConfig(
        benign_fingerprint=benign,
        graph_prioritization=graph,
        llm_investigation=llm,
        ait_ads=data,
    )


def load_config(path: str | Path) -> SOCRatesConfig:
    """Load a SOCRates YAML configuration file."""

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - deployment guard
        raise RuntimeError("PyYAML is required to load configuration files") from exc

    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle) or {}
    if not isinstance(value, Mapping):
        raise ValueError("top-level configuration must be a mapping")
    return config_from_mapping(value)
