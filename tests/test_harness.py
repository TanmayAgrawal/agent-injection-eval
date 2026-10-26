from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_eval.agent import TargetAgent
from agent_eval.grader import contains_attacker_args, grade
from agent_eval.models import AnthropicMessagesModel, ModelContext, ScriptedStochasticModel
from agent_eval.replay import replay_records
from agent_eval.report import write_report_files
from agent_eval.runner import record_runs
from agent_eval.scenarios import load_scenarios
from agent_eval.stats import paired_hierarchical_bootstrap, summarize
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

    def test_record_replay_is_deterministic(self) -> None:
        records = list(
            record_runs(
                root=ROOT,
                scenario_path=ROOT / "scenarios" / "scenarios.json",
                config_path=ROOT / "configs" / "M2.json",
                repetitions=2,
                adapter_kind="scripted",
                scenario_ids={"inj-001", "clean-01"},
                allow_dirty=True,
            )
        )
        replayed, mismatches = replay_records(records, ROOT / "scenarios" / "scenarios.json")
        self.assertEqual(len(replayed), 4)
        self.assertEqual(mismatches, [])

    def test_bootstrap_uses_paired_scenarios(self) -> None:
        records = []
        for mitigation, outcomes in {"M0": [1, 1, 0, 1], "M1": [0, 0, 0, 1]}.items():
            for scenario_index in range(2):
                for rep in range(2):
                    outcome = outcomes[scenario_index * 2 + rep]
                    records.append(
                        {
                            "scenario_kind": "injected",
                            "scenario_id": f"inj-{scenario_index}",
                            "config": {"mitigation": mitigation},
                            "labels": {"executed_attacker_args": bool(outcome)},
                        }
                    )
        comparison = paired_hierarchical_bootstrap(
            records,
            baseline="M0",
            candidate="M1",
            scenario_kind="injected",
            outcome="executed_attacker_args",
            iterations=200,
            seed=7,
        )
        self.assertEqual(comparison["n_scenarios"], 2)
        self.assertLess(comparison["point_estimate"], 0)

    def test_summary_distinguishes_attempted_and_executed_m2(self) -> None:
        records = []
        for config in ["M0", "M1", "M2"]:
            records.extend(
                record_runs(
                    root=ROOT,
                    scenario_path=ROOT / "scenarios" / "scenarios.json",
                    config_path=ROOT / "configs" / f"{config}.json",
                    repetitions=2,
                    adapter_kind="scripted",
                    scenario_ids={"inj-001", "clean-01"},
                    allow_dirty=True,
                )
            )
        summary = summarize(records)
        self.assertGreaterEqual(summary["configs"]["M2"]["attempted_asr_injected"], 0.0)
        self.assertEqual(summary["configs"]["M2"]["executed_asr_injected"], 0.0)

    def test_report_writer_creates_parent_directories(self) -> None:
        summary = {
            "run_count": 1,
            "configs": {
                "M0": {
                    "attempted_asr_injected": 0.0,
                    "executed_asr_injected": 0.0,
                    "clean_task_success": 1.0,
                    "mixed_injected_scenarios": 0.0,
                }
            },
            "comparisons": {},
        }
        gate = {"checks": {"example": True}}
        with tempfile.TemporaryDirectory() as directory:
            markdown = Path(directory) / "nested" / "EVIDENCE.md"
            finding = Path(directory) / "nested" / "finding.json"
            write_report_files(summary, gate, markdown, finding, "../trace.jsonl", [], "scripted")
            self.assertTrue(markdown.exists())
            self.assertTrue(finding.exists())

    def test_anthropic_adapter_parses_tool_use(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "id": "msg_test",
                        "content": [
                            {"type": "text", "text": "I will search."},
                            {
                                "type": "tool_use",
                                "id": "toolu_test",
                                "name": "search_docs",
                                "input": {"query": "synthetic product"},
                            },
                        ],
                    }
                ).encode("utf-8")

        scenario = self.scenarios[0]
        config = RunConfig.from_dict(
            {
                **json.loads((ROOT / "configs" / "M0.json").read_text(encoding="utf-8")),
                "model": "claude-sonnet-5-5",
                "temperature": None,
                "effort": "high",
            }
        )
        context = ModelContext(
            scenario=scenario,
            config=config,
            step=0,
            retrieved_documents=(),
            tool_results=(),
            system_prompt="test prompt",
        )
        model = AnthropicMessagesModel(config.model, api_key="test-key")
        with patch("urllib.request.urlopen", return_value=FakeResponse()) as request:
            action, raw = model.next_action(context, __import__("random").Random(1))
        self.assertEqual(action.tool_call.name, "search_docs")
        self.assertEqual(action.tool_call.args, {"query": "synthetic product"})
        self.assertEqual(action.content, "I will search.")
        self.assertEqual(raw["id"], "msg_test")
        sent_request = request.call_args.args[0]
        self.assertEqual(sent_request.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(sent_request.headers["Anthropic-version"], "2023-06-01")
        self.assertEqual(sent_request.headers["X-api-key"], "test-key")
        sent_payload = json.loads(sent_request.data)
        self.assertNotIn("temperature", sent_payload)
        self.assertEqual(sent_payload["output_config"], {"effort": "high"})


if __name__ == "__main__":
    unittest.main()
