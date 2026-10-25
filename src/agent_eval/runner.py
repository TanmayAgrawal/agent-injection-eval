from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterator

from .agent import TargetAgent
from .grader import grade
from .hashing import git_is_clean, stable_seed
from .models import OpenAICompatibleModel, ScriptedStochasticModel
from .scenarios import load_scenarios
from .trace import build_record, environment_record
from .types import RunConfig


def load_config(path: str | Path) -> RunConfig:
    return RunConfig.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def make_model(config: RunConfig, adapter_kind: str):
    if adapter_kind == "scripted":
        return ScriptedStochasticModel()
    if adapter_kind == "hosted":
        return OpenAICompatibleModel(config.model)
    raise ValueError(f"unknown adapter kind: {adapter_kind}")


def record_runs(
    *,
    root: str | Path,
    scenario_path: str | Path,
    config_path: str | Path,
    repetitions: int,
    adapter_kind: str,
    scenario_ids: set[str] | None = None,
    allow_dirty: bool = False,
) -> Iterator[dict]:
    project_root = Path(root).resolve()
    scenario_file = Path(scenario_path).resolve()
    config_file = Path(config_path).resolve()
    if not allow_dirty and not git_is_clean(project_root):
        raise RuntimeError("refusing to record against a dirty git worktree; commit changes or pass --allow-dirty")
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1")

    config = load_config(config_file)
    prompt_file = (project_root / config.prompt_file).resolve()
    prompt = prompt_file.read_text(encoding="utf-8")
    model = make_model(config, adapter_kind)
    agent = TargetAgent(model)
    scenarios = load_scenarios(scenario_file)
    if scenario_ids:
        scenarios = [scenario for scenario in scenarios if scenario.id in scenario_ids]
        missing = scenario_ids - {scenario.id for scenario in scenarios}
        if missing:
            raise ValueError(f"unknown scenario ids: {sorted(missing)}")

    environment = environment_record(project_root, scenario_file, config_file, prompt_file)
    for scenario in scenarios:
        for rep in range(repetitions):
            seed = stable_seed(environment["git_sha"], config.id, scenario.id, rep)
            step_traces, tools = agent.run(scenario, config, prompt, seed)
            steps = [step.to_dict() for step in step_traces]
            proposed_calls = [asdict(call) for call in tools.proposed_calls]
            executed_calls = [asdict(call) for call in tools.executed_calls]
            labels = grade(scenario, proposed_calls, executed_calls, steps)
            run_id = f"{config.id}:{scenario.id}:{rep:02d}:{seed:016x}"
            yield build_record(
                run_id=run_id,
                scenario=scenario,
                rep=rep,
                seed=seed,
                config=config,
                environment=environment,
                steps=steps,
                proposed_calls=proposed_calls,
                executed_calls=executed_calls,
                labels=labels,
                adapter_kind=adapter_kind,
            )

