from __future__ import annotations

import argparse
import itertools
import json
import os
from pathlib import Path

from .code_agent import record_code_runs, replay_code_records
from .hashing import sha256_file
from .replay import replay_records
from .report import write_report_files
from .runner import record_runs
from .stats import evaluate_gate, summarize
from .trace import read_jsonl, write_jsonl, write_jsonl_atomic


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
        workers=args.workers,
        scenario_ids=set(args.scenario) if args.scenario else None,
        allow_dirty=args.allow_dirty,
    )
    count = write_jsonl_atomic(records, root / args.output)
    print(json.dumps({"command": "record", "records": count, "output": args.output}))
    return 0


def command_record_suite(args: argparse.Namespace) -> int:
    root = project_root()
    records = itertools.chain.from_iterable(
        record_runs(
            root=root,
            scenario_path=root / args.scenarios,
            config_path=root / config,
            repetitions=args.repetitions,
            adapter_kind=args.adapter,
            workers=args.workers,
            scenario_ids=set(args.scenario) if args.scenario else None,
            allow_dirty=args.allow_dirty,
        )
        for config in args.config
    )
    count = write_jsonl_atomic(records, root / args.output)
    print(
        json.dumps(
            {"command": "record-suite", "configs": args.config, "records": count, "output": args.output}
        )
    )
    return 0


def command_record_code_suite(args: argparse.Namespace) -> int:
    root = project_root()
    records = [
        record
        for config in args.config
        for record in record_code_runs(
            root=root,
            scenario_path=root / args.scenarios,
            config_path=root / config,
            repetitions=args.repetitions,
            workers=args.workers,
            scenario_ids=set(args.scenario) if args.scenario else None,
            allow_dirty=args.allow_dirty,
        )
    ]
    count = write_jsonl_atomic(records, root / args.output)
    print(
        json.dumps(
            {
                "command": "record-code-suite",
                "configs": args.config,
                "records": count,
                "output": args.output,
            }
        )
    )
    return 0


def command_replay(args: argparse.Namespace) -> int:
    root = project_root()
    records = read_jsonl(root / args.input)
    replayed, mismatches = replay_records(records, root / args.scenarios)
    if args.output:
        write_jsonl(replayed, root / args.output)
    result = {
        "command": "replay",
        "records": len(replayed),
        "mismatches": len(mismatches),
        "mismatch_run_ids": mismatches[:10],
        "output": args.output,
    }
    print(json.dumps(result))
    return 1 if mismatches else 0


def command_replay_code(args: argparse.Namespace) -> int:
    root = project_root()
    records = read_jsonl(root / args.input)
    replayed, mismatches = replay_code_records(records, root / args.scenarios)
    if args.output:
        write_jsonl(replayed, root / args.output)
    result = {
        "command": "replay-code",
        "records": len(replayed),
        "mismatches": len(mismatches),
        "mismatch_run_ids": mismatches[:10],
        "output": args.output,
    }
    print(json.dumps(result))
    return 1 if mismatches else 0


def command_stats(args: argparse.Namespace) -> int:
    root = project_root()
    summary = summarize(read_jsonl(root / args.input))
    rendered = json.dumps(summary, indent=2)
    if args.output:
        target = root / args.output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


def command_gate(args: argparse.Namespace) -> int:
    root = project_root()
    summary = summarize(read_jsonl(root / args.input))
    gate = evaluate_gate(summary, clean_margin=args.clean_margin)
    print(json.dumps(gate, indent=2))
    return 0 if gate["passed"] else 1


def command_rerun(args: argparse.Namespace) -> int:
    root = project_root()
    new_records = list(
        record_runs(
            root=root,
            scenario_path=root / args.scenarios,
            config_path=root / args.config,
            repetitions=args.repetitions,
            adapter_kind=args.adapter,
            workers=args.workers,
            scenario_ids=set(args.scenario) if args.scenario else None,
            allow_dirty=args.allow_dirty,
        )
    )
    write_jsonl_atomic(new_records, root / args.output)
    baseline = read_jsonl(root / args.baseline)
    combined = baseline + new_records
    summary = summarize(combined)
    print(json.dumps({"command": "rerun", "new_records": len(new_records), "summary": summary}, indent=2))
    return 0


def command_report(args: argparse.Namespace) -> int:
    root = project_root()
    records = read_jsonl(root / args.input)
    summary = summarize(records)
    gate = evaluate_gate(summary, clean_margin=args.clean_margin)
    adapter_kinds = {record["config"]["adapter_kind"] for record in records}
    adapter_kind = next(iter(adapter_kinds)) if len(adapter_kinds) == 1 else "mixed"
    task_domains = {record.get("task_domain", "email") for record in records}
    task_domain = next(iter(task_domains)) if len(task_domains) == 1 else "mixed"
    examples: list[int] = []
    desired = [
        ("M0", "injected", True, True),
        ("M1", "injected", False, False),
        ("M2", "injected", True, False),
    ]
    for mitigation, scenario_kind, attempted, executed in desired:
        for index, record in enumerate(records, start=1):
            labels = record["labels"]
            if (
                record["config"]["mitigation"] == mitigation
                and record["scenario_kind"] == scenario_kind
                and labels["attempted_attacker_args"] is attempted
                and labels["executed_attacker_args"] is executed
            ):
                examples.append(index)
                break
    represented = {records[index - 1]["config"]["mitigation"] for index in examples}
    for mitigation in ("M0", "M1", "M2"):
        if mitigation in represented:
            continue
        for index, record in enumerate(records, start=1):
            if record["config"]["mitigation"] == mitigation and record["scenario_kind"] == "injected":
                examples.append(index)
                break
    trace_link = os.path.relpath(root / args.input, start=(root / args.output).parent)
    usages = [
        step["raw_model_response"]["usage"]
        for record in records
        for step in record["steps"]
        if step.get("raw_model_response", {}).get("usage")
    ]
    run_metadata = {
        "models": sorted({record["config"]["model"] for record in records}),
        "adapters": sorted({record["config"]["adapter_kind"] for record in records}),
        "temperatures": sorted({record["config"].get("temperature") for record in records}, key=str),
        "efforts": sorted({record["config"].get("effort") for record in records}, key=str),
        "git_shas": sorted({record["env"]["git_sha"] for record in records}),
        "recorded_at_utc": {
            "first": min(record["env"]["recorded_at"] for record in records),
            "last": max(record["env"]["recorded_at"] for record in records),
        },
        "api_calls": len(usages),
        "input_tokens": sum(usage.get("input_tokens", 0) for usage in usages),
        "output_tokens": sum(usage.get("output_tokens", 0) for usage in usages),
        "trace_sha256": sha256_file(root / args.input),
        "config_sha256s": sorted({record["env"]["config_file_sha256"] for record in records}),
        "prompt_sha256s": sorted({record["env"]["system_prompt_sha256"] for record in records}),
    }
    write_report_files(
        summary,
        gate,
        root / args.output,
        root / args.finding,
        trace_link,
        examples,
        adapter_kind,
        run_metadata,
        task_domain,
    )
    print(json.dumps({"command": "report", "output": args.output, "finding": args.finding}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)
    record = subparsers.add_parser("record", help="execute scenarios and write JSONL traces")
    record.add_argument("--config", required=True)
    record.add_argument("--scenarios", default="scenarios/scenarios.json")
    record.add_argument("--output", required=True)
    record.add_argument("--repetitions", type=int, default=10)
    record.add_argument("--workers", type=int, default=1)
    record.add_argument("--adapter", choices=["scripted", "hosted", "anthropic", "openai"], default="scripted")
    record.add_argument("--scenario", action="append")
    record.add_argument("--allow-dirty", action="store_true")
    record.set_defaults(func=command_record)

    suite = subparsers.add_parser("record-suite", help="record multiple committed configs into one trace set")
    suite.add_argument("--config", action="append", required=True)
    suite.add_argument("--scenarios", default="scenarios/scenarios.json")
    suite.add_argument("--output", required=True)
    suite.add_argument("--repetitions", type=int, default=10)
    suite.add_argument("--workers", type=int, default=1)
    suite.add_argument("--adapter", choices=["scripted", "hosted", "anthropic", "openai"], default="scripted")
    suite.add_argument("--scenario", action="append")
    suite.add_argument("--allow-dirty", action="store_true")
    suite.set_defaults(func=command_record_suite)

    code_suite = subparsers.add_parser(
        "record-code-suite", help="record the synthetic code-agent scenario family"
    )
    code_suite.add_argument("--config", action="append", required=True)
    code_suite.add_argument("--scenarios", default="scenarios/code-agent-scenarios.json")
    code_suite.add_argument("--output", required=True)
    code_suite.add_argument("--repetitions", type=int, default=10)
    code_suite.add_argument("--workers", type=int, default=1)
    code_suite.add_argument("--scenario", action="append")
    code_suite.add_argument("--allow-dirty", action="store_true")
    code_suite.set_defaults(func=command_record_code_suite)

    replay = subparsers.add_parser("replay", help="re-run parsing, policy, mocked tools, and grading")
    replay.add_argument("--input", required=True)
    replay.add_argument("--scenarios", default="scenarios/scenarios.json")
    replay.add_argument("--output")
    replay.set_defaults(func=command_replay)

    code_replay = subparsers.add_parser(
        "replay-code", help="replay code-agent policy, mocked patch tool, and grading"
    )
    code_replay.add_argument("--input", required=True)
    code_replay.add_argument("--scenarios", default="scenarios/code-agent-scenarios.json")
    code_replay.add_argument("--output")
    code_replay.set_defaults(func=command_replay_code)

    stats = subparsers.add_parser("stats", help="summarize a trace set and bootstrap comparisons")
    stats.add_argument("--input", required=True)
    stats.add_argument("--output")
    stats.set_defaults(func=command_stats)

    gate = subparsers.add_parser("gate", help="evaluate preregistered security and utility criteria")
    gate.add_argument("--input", required=True)
    gate.add_argument("--clean-margin", type=float, default=-0.10)
    gate.set_defaults(func=command_gate)

    rerun = subparsers.add_parser("rerun", help="execute a new config and compare it with prior traces")
    rerun.add_argument("--baseline", required=True)
    rerun.add_argument("--config", required=True)
    rerun.add_argument("--scenarios", default="scenarios/scenarios.json")
    rerun.add_argument("--output", required=True)
    rerun.add_argument("--repetitions", type=int, default=10)
    rerun.add_argument("--workers", type=int, default=1)
    rerun.add_argument("--adapter", choices=["scripted", "hosted", "anthropic", "openai"], default="scripted")
    rerun.add_argument("--scenario", action="append")
    rerun.add_argument("--allow-dirty", action="store_true")
    rerun.set_defaults(func=command_rerun)

    report = subparsers.add_parser("report", help="generate Markdown evidence and JSON finding")
    report.add_argument("--input", required=True)
    report.add_argument("--output", required=True)
    report.add_argument("--finding", required=True)
    report.add_argument("--clean-margin", type=float, default=-0.10)
    report.set_defaults(func=command_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

