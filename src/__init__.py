"""SOCRates: evidence-driven security alert triage framework."""

from .config import AITADSConfig, SOCRatesConfig, load_config
from .models import (
    AITADSRecord,
    AdjudicationLabel,
    AdjudicationResult,
    AlertGraphState,
    FingerprintDecision,
    FingerprintResult,
    GraphPrioritizationResult,
    NormalizedAlert,
    PipelineResult,
    PrioritizedAlert,
)
from .pipeline import SOCRatesPipeline
from .factory import build_default_pipeline
from .runner import run_ait_ads

__all__ = [
    "AdjudicationLabel",
    "AdjudicationResult",
    "AITADSConfig",
    "AITADSRecord",
    "AlertGraphState",
    "FingerprintDecision",
    "FingerprintResult",
    "GraphPrioritizationResult",
    "NormalizedAlert",
    "PipelineResult",
    "PrioritizedAlert",
    "SOCRatesConfig",
    "SOCRatesPipeline",
    "build_default_pipeline",
    "load_config",
    "run_ait_ads",
]

__version__ = "0.1.0"
