# Paper Results

This directory contains portable summaries of the final eight-scenario AIT-ADS
evaluation used by the paper.

## Layout

```text
results/
├── overall/
│   └── summary.json
├── module1/
│   ├── overall/
│   │   ├── summary.json
│   │   └── scenarios.csv
│   └── <scenario>/summary.json
├── module2/
│   ├── overall/
│   │   ├── summary.json
│   │   └── scenarios.csv
│   └── <scenario>/summary.json
└── module3/
    ├── overall/
    │   ├── summary.json
    │   └── scenarios.csv
    └── <scenario>/summary.json
```

The eight scenarios are `fox`, `harrison`, `russellmitchell`, `santos`,
`shaw`, `wardbeck`, `wheeler`, and `wilson`.

## Contents

- `overall/summary.json` connects the headline metrics from all three modules.
- `module1/` reports high-frequency aggregation, HAT filtering, workload
  reduction, and member-level attack preservation.
- `module2/` reports graph prioritization, candidate reduction, candidate
  composition, and member-level quality after ranking.
- `module3/` reports knowledge retrieval, LLM adjudication, confusion counts,
  classification metrics, and end-to-end workload reduction.

Every `overall/summary.json` contains aggregate totals and a per-scenario map.
The accompanying `scenarios.csv` provides the same scenario-level results in a
table-friendly format. Each scenario directory contains the more detailed JSON
summary for that scenario.

## Scope

This repository intentionally includes compact result summaries only. Large
runtime artifacts such as per-alert JSONL files, SQLite HAT and graph stores,
serialized Python context objects, and LLM checkpoints are excluded because the
final research workspace contains several gigabytes of those intermediate
files. The `source` field in each JSON summary records its current
repository-relative path under `results/`.
