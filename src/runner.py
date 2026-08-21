"""AIT-ADS experiment runner with a strict truth/data boundary."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .config import SOCRatesConfig
from .data import iter_ait_ads
from .factory import build_default_pipeline
from .models import MetaAlert
from .serialization import write_json, write_jsonl


def run_ait_ads(config: SOCRatesConfig) -> dict:
    """Bootstrap from the configured benign fraction and test the remainder."""

    data = config.ait_ads
    if data is None:
        raise ValueError("SOCRatesConfig.ait_ads is required for an AIT-ADS run")
    pipeline = build_default_pipeline(config)

    records = list(iter_ait_ads(data.input_paths))
    missing_label_count = sum(not record.label for record in records)
    if missing_label_count:
        raise ValueError(
            "AIT-ADS evaluation requires a label for every alert; "
            f"found {missing_label_count} unlabeled alerts"
        )

    outside_window_alerts = [
        record.alert
        for record in records
        if record.label == data.outside_attack_window_label
    ]
    source_counts: Counter[str] = Counter()
    for record in records:
        source_counts[record.detector_source] += 1

    outside_window_alerts.sort(key=lambda alert: (alert.timestamp, alert.alert_id))
    initialization_count = int(
        len(outside_window_alerts) * data.hat_initialization_fraction
    )
    if outside_window_alerts and initialization_count == 0:
        initialization_count = 1
    initialization_alerts = outside_window_alerts[:initialization_count]
    if not initialization_alerts:
        raise ValueError(
            "no outside-attack-window alerts are available for HAT initialization"
        )
    initialization_ids = {alert.alert_id for alert in initialization_alerts}
    test_records = [
        record for record in records if record.alert.alert_id not in initialization_ids
    ]
    test_alerts = [record.alert for record in test_records]
    test_label_sidecar = [
        (record.alert.alert_id, record.label) for record in test_records
    ]
    if len(test_alerts) + len(initialization_alerts) != len(records):
        raise AssertionError("FIT/TEST split must cover every input alert exactly once")

    bootstrap_fingerprint_ids = pipeline.bootstrap_benign_memory(initialization_alerts)
    result = pipeline.process(test_alerts)

    output_directory = Path(data.output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    write_jsonl(
        output_directory / "fingerprint_results.jsonl",
        result.fingerprint_results,
    )
    stage1_aggregation = result.stage1_aggregation
    write_jsonl(
        output_directory / "stage1_high_frequency_meta_alerts.jsonl",
        stage1_aggregation.meta_alerts if stage1_aggregation is not None else (),
    )
    write_jsonl(
        output_directory / "ranked_alerts.jsonl",
        result.graph_result.ranked_alerts,
    )
    write_jsonl(
        output_directory / "adjudications.jsonl",
        result.adjudications,
    )
    write_jsonl(
        output_directory / "deferred_candidates.jsonl",
        result.deferred_candidates,
    )

    # Labels are consulted only after every pipeline decision is frozen.
    label_counts = Counter(label or "<missing>" for _, label in test_label_sidecar)
    fingerprint_counts = Counter(
        item.decision.value for item in result.fingerprint_results
    )
    adjudication_counts = Counter(item.label.value for item in result.adjudications)
    bootstrap_aggregation = pipeline.bootstrap_aggregation
    bootstrap_meta_alerts = (
        bootstrap_aggregation.meta_alerts if bootstrap_aggregation is not None else ()
    )
    test_meta_alerts = (
        stage1_aggregation.meta_alerts if stage1_aggregation is not None else ()
    )
    hat_snapshot = pipeline.hat_snapshot_info
    graph_persistence = result.graph_result.persistence
    knowledge_base = pipeline.knowledge_base

    def behavior_counts(meta_alerts: tuple[MetaAlert, ...]) -> dict[str, int]:
        counts = Counter(
            str(alert.statistics.get("behavior_category") or "unknown")
            for alert in meta_alerts
        )
        return dict(sorted(counts.items()))

    def behavior_member_counts(
        meta_alerts: tuple[MetaAlert, ...],
    ) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for alert in meta_alerts:
            category = str(alert.statistics.get("behavior_category") or "unknown")
            counts[category] += len(alert.member_alert_ids)
        return dict(sorted(counts.items()))

    summary = {
        "input": {
            "source_counts": dict(sorted(source_counts.items())),
            "outside_attack_window_alerts": len(outside_window_alerts),
            "hat_initialization_fraction": data.hat_initialization_fraction,
            "hat_initialization_alerts": len(initialization_alerts),
            "hat_initialization_first_timestamp": (
                initialization_alerts[0].timestamp.isoformat()
            ),
            "hat_initialization_last_timestamp": (
                initialization_alerts[-1].timestamp.isoformat()
            ),
            "test_alerts": len(test_alerts),
            "fit_test_split": (
                "earliest benign fraction for FIT; remaining benign plus all "
                "false_positive and attack labels for TEST"
            ),
            "test_label_counts_evaluation_only": dict(sorted(label_counts.items())),
        },
        "stage_1": {
            **dict(sorted(fingerprint_counts.items())),
            "hat_persistence": {
                "status": pipeline.hat_state_status,
                "path": hat_snapshot.path if hat_snapshot is not None else None,
                "created_at": (
                    hat_snapshot.created_at.isoformat()
                    if hat_snapshot is not None
                    else None
                ),
                "fingerprint_count": (
                    hat_snapshot.fingerprint_count
                    if hat_snapshot is not None
                    else len(bootstrap_fingerprint_ids)
                ),
                "path_count": (
                    hat_snapshot.path_count if hat_snapshot is not None else None
                ),
                "total_support": (
                    hat_snapshot.total_support if hat_snapshot is not None else None
                ),
            },
            "initialization_objects_after_high_frequency_aggregation": (
                len(bootstrap_aggregation.alerts)
                if bootstrap_aggregation is not None
                else len(initialization_alerts)
            ),
            "initialization_high_frequency_meta_alerts": len(bootstrap_meta_alerts),
            "initialization_meta_alerts_by_behavior": behavior_counts(
                bootstrap_meta_alerts
            ),
            "test_objects_after_high_frequency_aggregation": (
                len(stage1_aggregation.alerts)
                if stage1_aggregation is not None
                else len(test_alerts)
            ),
            "test_high_frequency_meta_alerts": len(test_meta_alerts),
            "test_meta_alerts_by_behavior": behavior_counts(test_meta_alerts),
            "test_members_by_behavior": behavior_member_counts(test_meta_alerts),
            "test_members_inside_high_frequency_meta_alerts": (
                stage1_aggregation.aggregated_member_count
                if stage1_aggregation is not None
                else 0
            ),
        },
        "stage_2": {
            "ranked_alerts": len(result.graph_result.ranked_alerts),
            "candidates": len(result.graph_result.candidates),
            "meta_alerts": sum(
                1
                for item in result.graph_result.ranked_alerts
                if isinstance(item.alert, MetaAlert)
            ),
            "aggregation": "disabled; high-frequency aggregation is owned by stage_1",
            "graph_persistence": (
                {
                    "path": graph_persistence.path,
                    "saved_at": graph_persistence.saved_at.isoformat(),
                    "alert_node_count": graph_persistence.alert_node_count,
                    "entity_node_count": graph_persistence.entity_node_count,
                    "entity_edge_count": graph_persistence.entity_edge_count,
                    "member_edge_count": graph_persistence.member_edge_count,
                    "original_alert_count": graph_persistence.original_alert_count,
                    "candidate_count": graph_persistence.candidate_count,
                }
                if graph_persistence is not None
                else None
            ),
        },
        "stage_3": {
            "input_candidates_from_stage_2": len(result.graph_result.candidates),
            "adjudications": len(result.adjudications),
            "deferred_candidates": len(result.deferred_candidates),
            "labels": dict(sorted(adjudication_counts.items())),
            "max_candidates_per_run": config.llm_investigation.max_candidates_per_run,
            "retrieval": {
                "strategy": "dense_embedding_cosine_top_k",
                "embedding_model": config.llm_investigation.embedding_model,
                "embedding_dimensions": config.llm_investigation.embedding_dimensions,
                "similarity_threshold": (
                    config.llm_investigation.retrieval_similarity_threshold
                ),
                "top_k": config.llm_investigation.retrieval_top_k,
                "knowledge_database_path": (
                    str(getattr(knowledge_base, "database_path", None))
                    if getattr(knowledge_base, "database_path", None) is not None
                    else None
                ),
                "knowledge_database_status": getattr(
                    knowledge_base,
                    "status",
                    "legacy_in_memory",
                ),
                "pattern_count": (
                    len(knowledge_base) if knowledge_base is not None else 0
                ),
            },
        },
        "truth_boundary": (
            "AIT-ADS labels are excluded from NormalizedAlert, graph features, "
            "knowledge queries, and LLM prompts; TEST labels are summarized only "
            "after decisions."
        ),
    }
    write_json(output_directory / "run_summary.json", summary)
    return summary
