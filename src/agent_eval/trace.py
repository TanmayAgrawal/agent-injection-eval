from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .hashing import git_sha, sha256_file
from .types import RunConfig, Scenario


DEFAULT_LIMITATIONS = [
    "synthetic corpus and tasks",
    "single model configuration per recorded run",
    "hand-written injection families",
    "primary grader observes tool calls rather than semantic harm",
]


def environment_record(
    root: Path,
    scenario_file: Path,
    config_file: Path,
    prompt_file: Path,
) -> dict[str, Any]:
    lockfile = root / "requirements.lock"
    return {
        "git_sha": git_sha(root),
        "lockfile_sha256": sha256_file(lockfile),
        "scenario_file_sha256": sha256_file(scenario_file),
        "config_file_sha256": sha256_file(config_file),
        "system_prompt_sha256": sha256_file(prompt_file),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }


def build_record(
    *,
    run_id: str,
    scenario: Scenario,
    rep: int,
    seed: int,
    config: RunConfig,
    environment: dict[str, Any],
    steps: list[dict[str, Any]],
    proposed_calls: list[dict[str, Any]],
    executed_calls: list[dict[str, Any]],
    labels: dict[str, Any],
    adapter_kind: str,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "scenario_id": scenario.id,
        "scenario_group_id": scenario.group_id,
        "scenario_kind": scenario.kind,
        "task_family": scenario.task_family,
        "rep": rep,
        "seed": seed,
        "config": {
            "id": config.id,
            "model": config.model,
            "adapter_kind": adapter_kind,
            "temperature": config.temperature,
            "effort": config.effort,
            "mitigation": config.mitigation,
            "tools_version": config.tools_version,
            "policy_version": config.policy_version,
        },
        "env": environment,
        "attack": {
            "present": scenario.injection is not None,
            "placement": scenario.injection.placement if scenario.injection else None,
            "style": scenario.injection.style if scenario.injection else None,
            "target_step": scenario.injection.target_step if scenario.injection else None,
            "bypass_type": scenario.injection.bypass_type if scenario.injection else None,
        },
        "authorization": {
            "authorized_email": scenario.authorized_email,
            "attacker_email": scenario.injection.attacker_email if scenario.injection else None,
        },
        "steps": steps,
        "proposed_calls": proposed_calls,
        "executed_calls": executed_calls,
        "labels": labels,
        "limitations": limitations or list(DEFAULT_LIMITATIONS),
    }


def write_jsonl(records: Iterable[dict[str, Any]], destination: str | Path) -> int:
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
    return count


def read_jsonl(source: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with Path(source).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"{source}:{line_number}: invalid JSON") from error
    return records

