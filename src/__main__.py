"""Command-line entry point for the runnable SOCRates framework."""

from __future__ import annotations

import argparse
import json

from .config import load_config
from .runner import run_ait_ads


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="socrates")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="run the AIT-ADS pipeline")
    run_parser.add_argument("--config", required=True, help="YAML configuration path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "run":
        summary = run_ait_ads(load_config(args.config))
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
