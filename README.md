# SOCrates: An AI-Powered SOC Agent for Automated Network Alert Triage

This repository contains the artifacts for the paper *SOCrates: An AI-Powered SOC Agent for Automated Network Alert Triage*.

## Abstract

Security Operations Centers (SOCs) face severe alert fatigue as modern security systems generate massive volumes of redundant and false-positive alerts that exceed analysts' investigation capacity. Traditional rule-based and learning-based approaches can reduce part of this workload, but remain limited by rigid heuristics, insufficient contextual modeling, and poor adaptability to evolving enterprise environments. Large Language Models (LLMs) offer strong semantic understanding and reasoning capabilities for alert investigation, yet directly applying them to operational alert streams remains impractical due to limited inference throughput and a tendency to conservatively escalate context-poor benign alerts.

Motivated by an empirical study of operational alert streams, we propose SOCrates, an AI-powered SOC agent that performs scalable alert triage through a coarse-to-fine pipeline. First, SOCrates normalizes heterogeneous alerts, aggregates predefined high-frequency behaviors into traceable meta-alerts, and filters recurring benign activities using a Hierarchical Alert Event Tree (HAT) learned from analyst-confirmed benign examples. Second, it constructs a heterogeneous Alert-Entity Graph (AEG) and prioritizes the remaining alerts according to the rarity of their patterns, participating entities, and relations. Third, it retrieves enterprise-specific false-positive knowledge and reconstructs backward and forward behavioral context from the graph, enabling an LLM to produce evidence-grounded and interpretable adjudication results.

We evaluate SOCrates primarily on the public AIT-ADS benchmark. On 2,477,576 test alerts, SOCrates reduces the analyst-facing alert stream to only 709 alerts, achieving a 99.9714% alert reduction ratio while retaining 99.9970% of attack alerts, with an FPR of 0.6434% and an F1-score of 99.8637%. SOCrates also demonstrates a stronger overall balance of attack preservation, triage accuracy, and alert reduction than representative prior approaches. Moreover, it has been deployed in a real-world enterprise SOC for more than one year, demonstrating the practicality of combining lightweight alert reduction with evidence-driven LLM investigation at operational scale.

## Code Structure

The repository contains the paper, data-preparation utilities, curated evaluation
results, and the complete system implementation. The `src/` directory itself is
the Python package, so all commands below must be executed from the repository
root.

```text
SOCrates/
├── README.md                          # Project overview and usage instructions
├── AI_Powered_SOC_Agents_...pdf       # Paper manuscript
├── data/
│   ├── README.md                      # AIT-ADS download and preparation guide
│   ├── ait_ads_labeling.py            # Standalone per-alert label alignment utility
│   ├── ait_ads/                       # Downloaded raw AIT-ADS data (Git-ignored)
│   └── labeled/                       # Generated labeled inputs (Git-ignored)
├── results/
│   ├── README.md                      # Result organization and scope
│   ├── overall/                       # Combined headline metrics
│   ├── module1/                       # Aggregate and per-scenario Module 1 results
│   ├── module2/                       # Aggregate and per-scenario Module 2 results
│   └── module3/                       # Aggregate and per-scenario Module 3 results
└── src/
    ├── __main__.py                    # Command-line entry point
    ├── config.py                      # Configuration definitions and validation
    ├── factory.py                     # Default component assembly
    ├── models.py                      # Alert, Meta-Alert, graph, and verdict models
    ├── pipeline.py                    # Three-stage pipeline orchestration
    ├── progress.py                    # Runtime progress reporting
    ├── runner.py                      # AIT-ADS experiment runner
    ├── serialization.py              # JSON/JSONL result serialization
    ├── data/
    │   ├── ait_ads.py                 # AIT-ADS ingestion and normalization
    │   ├── ait_ads_labeling.py        # Importable label-alignment implementation
    │   └── tianyan.py                 # Tianyan ingestion and normalization
    └── modules/
        ├── benign_fingerprint/        # Module 1: aggregation and HAT filtering
        ├── graph_prioritization/      # Module 2: AEG construction and prioritization
        └── llm_investigation/         # Module 3: retrieval, context, and LLM adjudication
```

The three modules are connected by `src/pipeline.py`. Module 1 aggregates
high-frequency behavior and filters confirmed benign patterns. Module 2 assigns
graph-based anomaly scores to the remaining alerts. Module 3 combines
false-positive knowledge with bidirectional behavioral context to produce the
final verdict. Runtime state such as SQLite databases is written under `state/`
by the example configuration and is excluded from Git.

## Results

Portable summaries of the final eight-scenario AIT-ADS evaluation are organized
under [`results/`](results/README.md). They are divided into overall, Module 1,
Module 2, and Module 3 results; every module provides both aggregate metrics and
per-scenario summaries. Large runtime databases, checkpoints, and per-alert
intermediate files are intentionally excluded.

## How to Run

### 1. Install dependencies

Python 3.10 or later is recommended. Create a virtual environment and install the required packages:

```bash
cd /path/to/SOCrates
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install 'PyYAML>=6.0' 'numpy>=1.24' 'requests>=2.28'
```

### 2. Prepare the AIT-ADS data

Follow [`data/README.md`](data/README.md) to download AIT-ADS and the official per-alert labels, then use the bundled [`data/ait_ads_labeling.py`](data/ait_ads_labeling.py) utility to generate the evaluation files containing the required `label` field. The recommended locations are:

```text
data/labeled/fox_wazuh.json
data/labeled/fox_aminer.json
```

### 3. Configure model credentials

Module 3 calls the embedding and reasoning models through OpenAI-compatible APIs. Provide credentials through environment variables. Do not place API keys directly in the configuration file or commit them to Git:

```bash
export SOCRATES_EMBEDDING_API_KEY='YOUR_EMBEDDING_API_KEY'
export SOCRATES_LLM_API_KEY='YOUR_LLM_API_KEY'
```

### 4. Create a run configuration

Create `config.yaml` in the repository root. The following example runs the `fox` scenario. Replace the model endpoints, model names, and embedding dimensions with values appropriate for your providers:

```yaml
benign_fingerprint:
  hat_database_path: state/fox_hat.sqlite3
  high_frequency_preaggregation_enabled: true

graph_prioritization:
  graph_database_path: state/fox_alert_graph.sqlite3
  candidate_threshold: 0.7
  alert_weight: 0.3333333333333333
  entity_weight: 0.3333333333333333
  relation_weight: 0.3333333333333334

llm_investigation:
  knowledge_database_path: state/fox_false_positive_knowledge.sqlite3
  retrieval_top_k: 5
  retrieval_similarity_threshold: 0.7
  embedding_api_url: https://YOUR_EMBEDDING_PROVIDER/v1/embeddings
  embedding_model: YOUR_EMBEDDING_MODEL
  embedding_dimensions: 1024
  embedding_api_key_env: SOCRATES_EMBEDDING_API_KEY
  api_url: https://YOUR_LLM_PROVIDER/v1/chat/completions
  model: YOUR_LLM_MODEL
  api_key_env: SOCRATES_LLM_API_KEY
  max_output_tokens: 800
  # Use a small value for a smoke test. Remove it or set it to null to process all candidates.
  max_candidates_per_run: 10

ait_ads:
  input_paths:
    - data/labeled/fox_wazuh.json
    - data/labeled/fox_aminer.json
  output_directory: results/fox
  hat_initialization_fraction: 0.20
  outside_attack_window_label: benign
```

The HAT, alert graph, and false-positive knowledge base must use different persistence paths. Their parent directories are created automatically on the first run.

### 5. Run the pipeline

Run the following command from the repository root:

```bash
python -m src run --config config.yaml
```

Display the command-line help with:

```bash
python -m src --help
python -m src run --help
```

Results are written to the directory specified by `ait_ads.output_directory`. The output includes filtering decisions, Meta-Alerts, ranked alerts, LLM adjudications, and a run summary. A complete run invokes the configured models for every Module 3 candidate and may incur significant latency and API costs. Use a small `max_candidates_per_run` value for the initial smoke test.
