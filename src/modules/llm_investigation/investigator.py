"""Public interface of evidence-driven LLM investigation."""

from __future__ import annotations

from typing import Iterable, Protocol

from ...models import (
    AdjudicationResult,
    AlertGraphState,
    InvestigationContext,
    PrioritizedAlert,
)
from .adjudicator import EvidenceGuidedAdjudicator
from .context import BidirectionalContextRetriever
from .knowledge_base import FalsePositiveKnowledgeBase


class EvidenceDrivenInvestigator(Protocol):
    """Retrieve knowledge and graph evidence, then adjudicate a candidate."""

    def investigate(
        self,
        candidate: PrioritizedAlert,
        graph_state: AlertGraphState,
    ) -> AdjudicationResult:
        """Return the final evidence-linked triage result."""
        ...

    def investigate_many(
        self,
        candidates: Iterable[PrioritizedAlert],
        graph_state: AlertGraphState,
    ) -> tuple[AdjudicationResult, ...]:
        """Investigate candidates with batch retrieval when supported."""
        ...


class DefaultEvidenceDrivenInvestigator:
    """Retrieve benign memory and graph evidence before model adjudication."""

    def __init__(
        self,
        knowledge_base: FalsePositiveKnowledgeBase,
        context_retriever: BidirectionalContextRetriever,
        adjudicator: EvidenceGuidedAdjudicator,
    ) -> None:
        self.knowledge_base = knowledge_base
        self.context_retriever = context_retriever
        self.adjudicator = adjudicator

    def investigate(
        self,
        candidate: PrioritizedAlert,
        graph_state: AlertGraphState,
    ) -> AdjudicationResult:
        backward, forward = self.context_retriever.retrieve(
            candidate.alert,
            graph_state,
        )
        knowledge = self.knowledge_base.retrieve(candidate.alert)
        context = InvestigationContext(
            current_alert=candidate.alert,
            backward_evidence=backward,
            forward_evidence=forward,
            benign_knowledge=knowledge,
        )
        return self.adjudicator.adjudicate(context)

    def investigate_many(
        self,
        candidates: Iterable[PrioritizedAlert],
        graph_state: AlertGraphState,
    ) -> tuple[AdjudicationResult, ...]:
        """Batch embedding retrieval, then adjudicate each candidate."""

        candidate_batch = tuple(candidates)
        knowledge_batches = self.knowledge_base.retrieve_many(
            candidate.alert for candidate in candidate_batch
        )
        results: list[AdjudicationResult] = []
        for candidate, knowledge in zip(
            candidate_batch,
            knowledge_batches,
            strict=True,
        ):
            backward, forward = self.context_retriever.retrieve(
                candidate.alert,
                graph_state,
            )
            context = InvestigationContext(
                current_alert=candidate.alert,
                backward_evidence=backward,
                forward_evidence=forward,
                benign_knowledge=knowledge,
            )
            results.append(self.adjudicator.adjudicate(context))
        return tuple(results)
