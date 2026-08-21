"""Default component assembly for the runnable SOCRates reference pipeline."""

from __future__ import annotations

from .config import SOCRatesConfig
from .modules.benign_fingerprint import (
    HierarchicalAlertEventTree,
    HierarchicalBenignFingerprintFilter,
    JSONHATSnapshotStore,
    SQLiteHATStateStore,
    InMemoryBenignFingerprintRepository,
    PayloadAttributeTemplateExtractor,
    IdentityAlertPreprocessor,
    SessionHighFrequencyAlertAggregator,
    SHA256FingerprintCanonicalizer,
)
from .modules.graph_prioritization import (
    DefaultGraphAlertPrioritizer,
    SQLiteAlertGraphStore,
)
from .modules.llm_investigation import (
    ChatCompletionsAdjudicator,
    DefaultEvidenceDrivenInvestigator,
    EmbeddingFalsePositiveKnowledgeBase,
    GraphBidirectionalContextRetriever,
    OpenAICompatibleEmbeddingClient,
)
from .pipeline import SOCRatesPipeline


def build_default_pipeline(
    config: SOCRatesConfig | None = None,
) -> SOCRatesPipeline:
    """Build all three reference stages from one validated configuration."""

    settings = config or SOCRatesConfig()
    tree = HierarchicalAlertEventTree(
        template_extractor=PayloadAttributeTemplateExtractor(
            numeric_min_digits=(
                settings.benign_fingerprint.attribute_numeric_min_digits
            ),
            generalize_dynamic_values=False,
        ),
        # The persisted HAT is the exact evidence layer.  Subnet and payload
        # abstraction are learned separately by the filter from multiple
        # verified examples in the same branch.
        entity_ipv4_prefix_length=None,
        entity_ipv6_prefix_length=None,
    )
    canonicalizer = SHA256FingerprintCanonicalizer()
    repository = InMemoryBenignFingerprintRepository()
    fingerprint_filter = HierarchicalBenignFingerprintFilter(
        tree=tree,
        canonicalizer=canonicalizer,
        repository=repository,
        config=settings.benign_fingerprint,
    )
    database_path = settings.benign_fingerprint.hat_database_path
    legacy_state_path = settings.benign_fingerprint.hat_state_path
    if database_path is not None:
        hat_state_store = SQLiteHATStateStore(
            database_path,
            tree=tree,
            repository=repository,
            canonicalizer=canonicalizer,
            config=settings.benign_fingerprint,
        )
    elif legacy_state_path is not None:
        hat_state_store = JSONHATSnapshotStore(
            legacy_state_path,
            tree=tree,
            repository=repository,
            canonicalizer=canonicalizer,
            config=settings.benign_fingerprint,
        )
    else:
        hat_state_store = None
    embedding_client = OpenAICompatibleEmbeddingClient(settings.llm_investigation)
    knowledge_base = EmbeddingFalsePositiveKnowledgeBase(
        embedding_client,
        settings.llm_investigation,
    )
    investigator = DefaultEvidenceDrivenInvestigator(
        knowledge_base=knowledge_base,
        context_retriever=GraphBidirectionalContextRetriever(
            settings.llm_investigation
        ),
        adjudicator=ChatCompletionsAdjudicator(
            settings.llm_investigation,
        ),
    )
    graph_database_path = settings.graph_prioritization.graph_database_path
    graph_store = (
        SQLiteAlertGraphStore(
            graph_database_path,
            settings.graph_prioritization,
        )
        if graph_database_path is not None
        else None
    )
    return SOCRatesPipeline(
        fingerprint_filter=fingerprint_filter,
        graph_prioritizer=DefaultGraphAlertPrioritizer(
            settings.graph_prioritization,
            graph_store=graph_store,
        ),
        investigator=investigator,
        max_investigations=settings.llm_investigation.max_candidates_per_run,
        knowledge_base=knowledge_base,
        hat_state_store=hat_state_store,
        alert_preprocessor=(
            SessionHighFrequencyAlertAggregator(
                inactivity_threshold_seconds=(
                    settings.benign_fingerprint.preaggregation_inactivity_threshold_seconds
                ),
                maximum_session_duration_seconds=(
                    settings.benign_fingerprint.high_frequency_max_session_duration_seconds
                ),
                minimum_members=(
                    settings.benign_fingerprint.preaggregation_min_members
                ),
            )
            if settings.benign_fingerprint.preaggregation_enabled
            else IdentityAlertPreprocessor()
        ),
    )
