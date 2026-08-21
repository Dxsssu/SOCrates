"""Module 1: hierarchical benign fingerprint filtering."""

from .attribute_template import (
    AttributeTemplateExtractor,
    PayloadAttributeTemplateExtractor,
    normalize_payload_text,
)
from .event_tree import (
    EMPTY_ATTRIBUTE_TEMPLATE,
    LAYER_ORDER,
    NULL_VALUE,
    MULTIPLE_VALUE,
    AlertEventTree,
    AlertLayer,
    AlertPath,
    AlertTreeNode,
    HierarchicalAlertEventTree,
    TreeMatch,
    canonicalize_entity_value,
)
from .high_frequency_aggregation import (
    AlertPreprocessor,
    EntityRuleWindowAlertAggregator,
    HighFrequencyBehavior,
    IdentityAlertPreprocessor,
    SessionHighFrequencyAlertAggregator,
    SessionScanAlertAggregator,
    brute_force_family,
    denial_of_service_family,
    dns_tunnel_family,
    high_frequency_behavior,
    scan_family,
)
from .filter import BenignFingerprintFilter, HierarchicalBenignFingerprintFilter
from .fingerprint import FingerprintCanonicalizer, SHA256FingerprintCanonicalizer
from .repository import (
    BenignFingerprintRepository,
    FingerprintKind,
    FingerprintRecord,
    InMemoryBenignFingerprintRepository,
)
from .generalization import (
    GeneralizationInference,
    TypedConstraint,
    infer_generalized_path,
    matches_generalized_path,
)
from .persistence import (
    HATSnapshotError,
    HATSnapshotInfo,
    HATStateStore,
    JSONHATSnapshotStore,
    SQLiteHATStateStore,
)

__all__ = [
    "AlertEventTree",
    "AlertLayer",
    "AlertPath",
    "AlertTreeNode",
    "AttributeTemplateExtractor",
    "BenignFingerprintFilter",
    "BenignFingerprintRepository",
    "EMPTY_ATTRIBUTE_TEMPLATE",
    "FingerprintCanonicalizer",
    "FingerprintKind",
    "FingerprintRecord",
    "GeneralizationInference",
    "HierarchicalAlertEventTree",
    "HierarchicalBenignFingerprintFilter",
    "InMemoryBenignFingerprintRepository",
    "LAYER_ORDER",
    "NULL_VALUE",
    "MULTIPLE_VALUE",
    "PayloadAttributeTemplateExtractor",
    "SHA256FingerprintCanonicalizer",
    "TreeMatch",
    "TypedConstraint",
    "canonicalize_entity_value",
    "normalize_payload_text",
    "AlertPreprocessor",
    "EntityRuleWindowAlertAggregator",
    "HighFrequencyBehavior",
    "IdentityAlertPreprocessor",
    "SessionHighFrequencyAlertAggregator",
    "SessionScanAlertAggregator",
    "brute_force_family",
    "denial_of_service_family",
    "dns_tunnel_family",
    "high_frequency_behavior",
    "scan_family",
    "infer_generalized_path",
    "matches_generalized_path",
    "HATSnapshotError",
    "HATSnapshotInfo",
    "HATStateStore",
    "JSONHATSnapshotStore",
    "SQLiteHATStateStore",
]
