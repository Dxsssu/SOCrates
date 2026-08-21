"""Module 3: evidence-driven LLM investigation."""

from .adjudicator import (
    ChatCompletionsAdjudicator,
    EvidenceGuidedAdjudicator,
    LLMConfigurationError,
)
from .context import BidirectionalContextRetriever, GraphBidirectionalContextRetriever
from .embedding import (
    EmbeddingConfigurationError,
    EmbeddingProvider,
    EmbeddingResponseError,
    OpenAICompatibleEmbeddingClient,
)
from .investigator import DefaultEvidenceDrivenInvestigator, EvidenceDrivenInvestigator
from .knowledge_builder import (
    ChatCompletionsFalsePositivePatternGenerator,
    FalsePositivePatternGenerator,
    KnowledgePatternCache,
    NormalizedPayloadClusterer,
    PatternGenerationConfigurationError,
    PatternGenerationResponseError,
    PayloadCluster,
    ScenarioTrainingSample,
    knowledge_document,
    sample_scenario_false_positives,
)
from .knowledge_base import (
    EmbeddingFalsePositiveKnowledgeBase,
    FalsePositiveKnowledgeBase,
    KnowledgeDocument,
    KnowledgeVectorStoreError,
)

__all__ = [
    "BidirectionalContextRetriever",
    "ChatCompletionsAdjudicator",
    "ChatCompletionsFalsePositivePatternGenerator",
    "DefaultEvidenceDrivenInvestigator",
    "EmbeddingConfigurationError",
    "EmbeddingFalsePositiveKnowledgeBase",
    "EmbeddingProvider",
    "EmbeddingResponseError",
    "EvidenceDrivenInvestigator",
    "EvidenceGuidedAdjudicator",
    "FalsePositiveKnowledgeBase",
    "FalsePositivePatternGenerator",
    "GraphBidirectionalContextRetriever",
    "KnowledgeVectorStoreError",
    "KnowledgeDocument",
    "KnowledgePatternCache",
    "LLMConfigurationError",
    "OpenAICompatibleEmbeddingClient",
    "NormalizedPayloadClusterer",
    "PatternGenerationConfigurationError",
    "PatternGenerationResponseError",
    "PayloadCluster",
    "ScenarioTrainingSample",
    "knowledge_document",
    "sample_scenario_false_positives",
]
