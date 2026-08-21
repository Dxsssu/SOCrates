"""Compatibility imports for the former scan-only module-one aggregator."""

from .high_frequency_aggregation import (
    AlertPreprocessor,
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

__all__ = [
    "AlertPreprocessor",
    "HighFrequencyBehavior",
    "IdentityAlertPreprocessor",
    "SessionHighFrequencyAlertAggregator",
    "SessionScanAlertAggregator",
    "brute_force_family",
    "denial_of_service_family",
    "dns_tunnel_family",
    "high_frequency_behavior",
    "scan_family",
]
