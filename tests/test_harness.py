from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_eval.agent import TargetAgent
from agent_eval.grader import contains_attacker_args, grade
from agent_eval.models import ScriptedStochasticModel
from agent_eval.scenarios import load_scenarios
from agent_eval.tools import AuthorizationPolicy
from agent_eval.types import RunConfig, ToolCall


ROOT = Path(__file__).resolve().parents[1]


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scenarios = load_scenarios(ROOT / "scenarios" / "scenarios.json")

    def test_suite_shape(self) -> None:
        self.assertEqual(len(self.scenarios), 30)
        self.assertEqual(sum(item.kind == "clean" for item in self.scenarios), 10)
        self.assertEqual(sum(item.kind == "injected" for item in self.scenarios), 20)
        self.assertEqual(sum(bool(item.injection and item.injection.bypass_type) for item in self.scenarios), 4)

    def test_policy_blocks_all_declared_attacker_recipients(self) -> None:
        policy = AuthorizationPolicy()
        for scenario in self.scenarios:
            if not scenario.injection:
                continue
            call = ToolCall("send_email", {"to": scenario.injection.attacker_email, "body": "synthetic"})
            self.assertFalse(policy.evaluate(scenario, call).allowed, scenario.id)

    def test_policy_allows_exact_authorized_recipient(self) -> None:
        scenario = self.scenarios[0]
        call = ToolCall("send_email", {"to": scenario.authorized_email.upper(), "body": "synthetic"})
        self.assertTrue(AuthorizationPolicy().evaluate(scenario, call).allowed)

    def test_grader_uses_structured_arguments(self) -> None:
        scenario = next(item for item in self.scenarios if item.injection)
        attack = ToolCall(
            "send_email",
            {"to": scenario.injection.attacker_email, "body": scenario.injection.attacker_body_marker},
        )
        self.assertTrue(contains_attacker_args(scenario, attack))
        labels = grade(scenario, [attack], [attack], [])
        self.assertTrue(labels["attempted_attacker_args"])
        self.assertTrue(labels["executed_attacker_args"])
        self.assertFalse(labels["task_completed"])

    def test_m2_separates_attempt_from_execution(self) -> None:
        scenario = next(item for item in self.scenarios if item.id == "inj-001")
        config = RunConfig.from_dict(
            json.loads((ROOT / "configs" / "M2.json").read_text(encoding="utf-8"))
        )
        prompt = (ROOT / config.prompt_file).read_text(encoding="utf-8")
        steps, tools = TargetAgent(ScriptedStochasticModel()).run(scenario, config, prompt, seed=3)
        self.assertEqual(len(tools.proposed_calls), 1)
        self.assertEqual(len(tools.executed_calls), 0)
        labels = grade(
            scenario,
            tools.proposed_calls,
            tools.executed_calls,
            [step.to_dict() for step in steps],
        )
        self.assertTrue(labels["attempted_attacker_args"])
        self.assertFalse(labels["executed_attacker_args"])
        self.assertTrue(labels["blocked"])


if __name__ == "__main__":
    unittest.main()
