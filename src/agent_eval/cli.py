from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runner import record_runs
from .trace import write_jsonl


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def command_record(args: argparse.Namespace) -> int:
    root = project_root()
    records = record_runs(
        root=root,
        scenario_path=root / args.scenarios,
        config_path=root / args.config,
        repetitions=args.repetitions,
        adapter_kind=args.adapter,
        scenario_ids=set(args.scenario) if args.scenario else None,
        allow_dirty=args.allow_dirty,
    )
    count = write_jsonl(records, root / args.output)
    print(json.dumps({"command": "record", "records": count, "output": args.output}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)
    record = subparsers.add_parser("record", help="execute scenarios and write JSONL traces")
    record.add_argument("--config", required=True)
    record.add_argument("--scenarios", default="scenarios/scenarios.json")
    record.add_argument("--output", required=True)
    record.add_argument("--repetitions", type=int, default=10)
    record.add_argument("--adapter", choices=["scripted", "hosted"], default="scripted")
    record.add_argument("--scenario", action="append")
    record.add_argument("--allow-dirty", action="store_true")
    record.set_defaults(func=command_record)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

