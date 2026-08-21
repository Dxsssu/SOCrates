"""Attach official AIT-ADS event labels and SOCRates triage labels.

The official AIT-ADS analysis archive stores one label row per raw alert in a
deterministic order: Wazuh/Suricata records first, followed by AMiner records.
This module validates that alignment before adding one ``label`` field to
every raw JSON object.  The final label follows a strict precedence order:

1. Alerts outside all attack windows are labeled ``benign``.
2. Alerts inside an attack window without an event-level match are labeled
   ``false_positive``.
3. Alerts inside an attack window with an event-level match use that official
   event label directly, for example ``dns_scan`` or ``webshell_cmd``.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import zipfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Mapping, TextIO


SCENARIOS = (
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)

LABEL_FIELDS = ("label", "time_label", "event_label", "triage_label")


@dataclass(slots=True)
class FileStatistics:
    source_file: str
    output_file: str
    records: int = 0
    detector_sources: Counter[str] = field(default_factory=Counter)
    labels: Counter[str] = field(default_factory=Counter)

    def serializable(self) -> dict:
        value = asdict(self)
        value["detector_sources"] = dict(sorted(self.detector_sources.items()))
        value["labels"] = dict(sorted(self.labels.items()))
        return value


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=project_root / "ait_ads",
    )
    parser.add_argument(
        "--label-archive",
        type=Path,
        default=project_root / "alert-data-set" / "alerts_csv" / "alerts_csv.zip",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "ait_ads_label",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=SCENARIOS,
        default=list(SCENARIOS),
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing labeled JSON files.",
    )
    return parser.parse_args()


def _metadata(alert: Mapping, source_kind: str) -> tuple[str, str, str]:
    if source_kind == "wazuh":
        description = str(alert["rule"]["description"])
        detector_source = (
            "suricata"
            if alert.get("location") == "/var/log/suricata/eve.json"
            else "wazuh"
        )
        expected_name = (
            description
            if description.startswith("Suricata: ")
            else f"Wazuh: {description}"
        )
        return detector_source, expected_name, str(alert["agent"]["ip"])

    if source_kind == "aminer":
        return (
            "aminer",
            str(alert["AnalysisComponent"]["AnalysisComponentName"]),
            str(alert["AMiner"]["ID"]),
        )

    raise ValueError(f"Unsupported source kind: {source_kind}")


def _final_label(time_label: str, event_label: str) -> str:
    if time_label == "false_positive" or time_label.startswith("false_positive"):
        return "benign"
    if event_label != "-":
        return event_label
    return "false_positive"


def _iter_jsonl(handle: TextIO, source_path: Path) -> Iterator[tuple[int, dict]]:
    for line_number, raw_line in enumerate(handle, 1):
        if not raw_line.strip():
            continue
        try:
            alert = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON at {source_path}:{line_number}: {exc}"
            ) from exc
        if not isinstance(alert, dict):
            raise ValueError(f"Expected a JSON object at {source_path}:{line_number}")
        collisions = set(LABEL_FIELDS).intersection(alert)
        if collisions:
            raise ValueError(
                f"Input already contains label fields at {source_path}:{line_number}: "
                f"{sorted(collisions)}"
            )
        yield line_number, alert


def _validate_label_header(reader: csv.DictReader, scenario: str) -> None:
    expected = [
        "time",
        "name",
        "ip",
        "host",
        "short",
        "time_label",
        "event_label",
    ]
    if reader.fieldnames != expected:
        raise ValueError(
            f"Unexpected official label columns for {scenario}: {reader.fieldnames}"
        )


def _label_file(
    source_path: Path,
    output_handle: TextIO,
    labels: csv.DictReader,
    source_kind: str,
) -> FileStatistics:
    statistics = FileStatistics(
        source_file=source_path.name,
        output_file=source_path.name,
    )
    with source_path.open("r", encoding="utf-8") as input_handle:
        for source_line, alert in _iter_jsonl(input_handle, source_path):
            try:
                official = next(labels)
            except StopIteration as exc:
                raise ValueError(
                    f"Official labels ended before {source_path}:{source_line}"
                ) from exc

            detector_source, expected_name, expected_ip = _metadata(alert, source_kind)
            if official["name"] != expected_name or official["ip"] != expected_ip:
                raise ValueError(
                    f"Label alignment failed at {source_path}:{source_line}: "
                    f"expected name={expected_name!r}, ip={expected_ip!r}; "
                    f"got name={official['name']!r}, ip={official['ip']!r}"
                )

            time_label = official["time_label"]
            event_label = official["event_label"]
            final_label = _final_label(time_label, event_label)
            alert["label"] = final_label
            output_handle.write(
                json.dumps(alert, ensure_ascii=False, separators=(",", ":")) + "\n"
            )

            statistics.records += 1
            statistics.detector_sources[detector_source] += 1
            statistics.labels[final_label] += 1
    return statistics


def label_scenario(
    scenario: str,
    input_dir: Path,
    label_archive: Path,
    output_dir: Path,
    overwrite: bool,
) -> dict:
    source_specs = (
        (input_dir / f"{scenario}_wazuh.json", "wazuh"),
        (input_dir / f"{scenario}_aminer.json", "aminer"),
    )
    output_paths = tuple(output_dir / source.name for source, _ in source_specs)
    for source_path in (source for source, _ in source_specs):
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
    if not overwrite:
        existing = [path for path in output_paths if path.exists()]
        if existing:
            raise FileExistsError(f"Refusing to overwrite: {existing}")

    temp_paths = tuple(path.with_suffix(path.suffix + ".tmp") for path in output_paths)
    for temp_path in temp_paths:
        temp_path.unlink(missing_ok=True)

    file_statistics: list[FileStatistics] = []
    member = f"alerts_csv/{scenario}_alerts.txt"
    try:
        with zipfile.ZipFile(label_archive) as archive:
            with archive.open(member, "r") as binary_labels:
                with io.TextIOWrapper(binary_labels, encoding="utf-8", newline="") as text_labels:
                    labels = csv.DictReader(text_labels)
                    _validate_label_header(labels, scenario)
                    for (source_path, source_kind), temp_path in zip(
                        source_specs, temp_paths, strict=True
                    ):
                        with temp_path.open("w", encoding="utf-8") as output_handle:
                            stats = _label_file(
                                source_path,
                                output_handle,
                                labels,
                                source_kind,
                            )
                            stats.output_file = str(output_paths[len(file_statistics)])
                            file_statistics.append(stats)
                    extra = next(labels, None)
                    if extra is not None:
                        raise ValueError(
                            f"Official labels contain extra rows after {scenario} inputs"
                        )

        for temp_path, output_path in zip(temp_paths, output_paths, strict=True):
            os.replace(temp_path, output_path)
    except Exception:
        for temp_path in temp_paths:
            temp_path.unlink(missing_ok=True)
        raise

    totals = Counter()
    detector_totals = Counter()
    for stats in file_statistics:
        totals.update(stats.labels)
        detector_totals.update(stats.detector_sources)
    return {
        "scenario": scenario,
        "records": sum(stats.records for stats in file_statistics),
        "detector_sources": dict(sorted(detector_totals.items())),
        "labels": dict(sorted(totals.items())),
        "files": [stats.serializable() for stats in file_statistics],
    }


def _write_summary(output_dir: Path, scenarios: list[dict]) -> Path:
    label_totals = Counter()
    detector_totals = Counter()
    for scenario in scenarios:
        label_totals.update(scenario["labels"])
        detector_totals.update(scenario["detector_sources"])

    summary = {
        "labeling_policy": {
            "benign": "outside an annotated attack time window",
            "false_positive": "inside an attack window and event_label is '-'",
            "attack_event": (
                "inside an attack window and labeled with the matched official "
                "event_label"
            ),
        },
        "record_count": sum(item["records"] for item in scenarios),
        "detector_sources": dict(sorted(detector_totals.items())),
        "labels": dict(sorted(label_totals.items())),
        "scenarios": sorted(scenarios, key=lambda item: item["scenario"]),
    }
    destination = output_dir / "labeling_summary.json"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)
    return destination


def main() -> None:
    args = parse_args()
    if args.workers < 1:
        raise ValueError("--workers must be at least 1")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not args.label_archive.is_file():
        raise FileNotFoundError(args.label_archive)

    results: list[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                label_scenario,
                scenario,
                args.input_dir,
                args.label_archive,
                args.output_dir,
                args.overwrite,
            ): scenario
            for scenario in args.scenarios
        }
        for future in as_completed(futures):
            scenario = futures[future]
            result = future.result()
            results.append(result)
            print(
                f"[{scenario}] labeled {result['records']:,} alerts: "
                f"{result['labels']}",
                flush=True,
            )

    summary_path = _write_summary(args.output_dir, results)
    print(
        f"Wrote {sum(item['records'] for item in results):,} labeled alerts "
        f"and summary {summary_path}",
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"AIT-ADS labeling failed: {exc}", file=sys.stderr)
        raise
