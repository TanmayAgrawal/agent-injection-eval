from __future__ import annotations

import random
from dataclasses import asdict
from typing import Any

from .models import ModelAdapter, ModelContext
from .tools import AuthorizationPolicy, MockTools
from .types import RunConfig, Scenario, StepTrace


class TargetAgent:
    def __init__(self, model: ModelAdapter, policy: AuthorizationPolicy | None = None):
        self.model = model
        self.policy = policy or AuthorizationPolicy()

    def run(
        self,
        scenario: Scenario,
        config: RunConfig,
        system_prompt: str,
        seed: int,
    ) -> tuple[list[StepTrace], MockTools]:
        rng = random.Random(seed)
        tools = MockTools(scenario)
        retrieved: tuple[dict[str, Any], ...] = ()
        tool_results: list[dict[str, Any]] = []
        traces: list[StepTrace] = []

        for step_index in range(config.max_steps):
            context = ModelContext(
                scenario=scenario,
                config=config,
                step=step_index,
                retrieved_documents=retrieved,
                tool_results=tuple(tool_results),
                system_prompt=system_prompt,
            )
            action, raw_response = self.model.next_action(context, rng)
            step = StepTrace(
                i=step_index,
                model_output=action.content,
                raw_model_response=raw_response,
                tool_call=asdict(action.tool_call) if action.tool_call else None,
            )
            if action.tool_call is None:
                traces.append(step)
                break

            call = action.tool_call
            if call.name == "search_docs":
                documents, result = tools.search_docs(str(call.args.get("query", "")))
                retrieved = tuple(asdict(document) for document in documents)
                step.retrieved = [document.id for document in documents]
                step.tool_result = result
                tool_results.append(
                    {"tool_call_id": f"step-{step_index}", "name": call.name, "result": result}
                )
                traces.append(step)
                continue

            tools.propose(call)
            decision = self.policy.evaluate(scenario, call)
            enforce_gate = config.mitigation == "M2"
            allowed = decision.allowed if enforce_gate else True
            step.policy_decision = {
                "enforced": enforce_gate,
                "allowed": allowed,
                "policy_would_allow": decision.allowed,
                "reason": decision.reason,
                "normalized_args": decision.normalized_args,
            }
            if allowed:
                step.tool_result = tools.execute(call)
            else:
                step.tool_result = {"ok": False, "blocked": True, "reason": decision.reason}
            traces.append(step)
            break
        return traces, tools

