from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .grader import grade
from .scenarios import load_scenarios
from .tools import AuthorizationPolicy, MockTools
from .types import ToolCall


def replay_record(record: dict[str, Any], scenarios_by_id: dict[str, Any]) -> dict[str, Any]:
    scenario = scenarios_by_id[record["scenario_id"]]
    tools = MockTools(scenario)
    policy = AuthorizationPolicy()
    replay_steps: list[dict[str, Any]] = []

    for recorded_step in record["steps"]:
        step = {
            "i": recorded_step["i"],
            "retrieved": list(recorded_step.get("retrieved", [])),
            "model_output": recorded_step.get("model_output", ""),
            "tool_call": recorded_step.get("tool_call"),
            "tool_result": None,
            "policy_decision": None,
        }
        raw_call = recorded_step.get("tool_call")
        if raw_call is None:
            replay_steps.append(step)
            continue
        call = ToolCall(name=raw_call["name"], args=dict(raw_call.get("args", {})))
        if call.name == "search_docs":
            documents, result = tools.search_docs(str(call.args.get("query", "")))
            step["retrieved"] = [document.id for document in documents]
            step["tool_result"] = result
            replay_steps.append(step)
            continue

        tools.propose(call)
        decision = policy.evaluate(scenario, call)
        enforced = record["config"]["mitigation"] == "M2"
        allowed = decision.allowed if enforced else True
        step["policy_decision"] = {
            "enforced": enforced,
            "allowed": allowed,
            "policy_would_allow": decision.allowed,
            "reason": decision.reason,
            "normalized_args": decision.normalized_args,
        }
        if allowed:
            step["tool_result"] = tools.execute(call)
        else:
            step["tool_result"] = {"ok": False, "blocked": True, "reason": decision.reason}
        replay_steps.append(step)

    proposed = [asdict(call) for call in tools.proposed_calls]
    executed = [asdict(call) for call in tools.executed_calls]
    labels = grade(scenario, proposed, executed, replay_steps)
    return {
        **record,
        "steps": replay_steps,
        "proposed_calls": proposed,
        "executed_calls": executed,
        "labels": labels,
        "replay": {"source_run_id": record["run_id"], "deterministic_downstream_only": True},
    }


def replay_records(records: list[dict[str, Any]], scenario_path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    scenarios = {scenario.id: scenario for scenario in load_scenarios(scenario_path)}
    replayed: list[dict[str, Any]] = []
    mismatches: list[str] = []
    for record in records:
        replayed_record = replay_record(record, scenarios)
        replayed.append(replayed_record)
        if replayed_record["labels"] != record["labels"]:
            mismatches.append(record["run_id"])
    return replayed, mismatches

