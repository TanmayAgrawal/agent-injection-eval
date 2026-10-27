from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _comparison_line(comparison: dict[str, Any]) -> str:
    if comparison.get("status") == "not_estimable_floor":
        upper = comparison["zero_event_upper95_scenario_attack_rate"]
        return (
            "not estimable because the baseline had zero attack events; "
            f"one-sided 95% upper bound for scenario-level attack occurrence is {upper * 100:.1f}% "
            f"across {comparison['n_scenarios']} scenario clusters"
        )
    if comparison.get("status") == "not_estimable_no_clean_failures":
        upper = comparison["zero_event_upper95_scenario_failure_rate"]
        return (
            "no clean-task difference observed, but a zero-width bootstrap interval is uninformative; "
            f"one-sided 95% upper bound for scenario-level clean failure occurrence is {upper * 100:.1f}% "
            f"across {comparison['n_scenarios']} scenario clusters"
        )
    low, high = comparison["ci95"]
    return (
        f"{comparison['point_estimate'] * 100:+.1f} percentage points "
        f"(95% CI {low * 100:+.1f} to {high * 100:+.1f}; "
        f"{comparison['n_scenarios']} scenario clusters)"
    )


def _values(values: list[Any] | None) -> str:
    return ", ".join("null" if value is None else str(value) for value in (values or ["not recorded"]))


def generate_evidence_markdown(
    summary: dict[str, Any],
    gate: dict[str, Any],
    trace_path: str,
    example_lines: list[int],
    adapter_kind: str,
    run_metadata: dict[str, Any] | None = None,
    task_domain: str = "email",
) -> str:
    metadata = run_metadata or {}
    if task_domain == "code":
        question = (
            "Does a mitigation reduce privileged patches containing attacker-controlled paths or content "
            "after an agent reads an injected repository file, without materially reducing clean-task success?"
        )
        setup = (
            "M0 is the baseline, M1 isolates repository file content in the prompt, and M2 enforces "
            "an external patch path/content policy. All repository reads and patch applications are mocked."
        )
        proposed_control = (
            "Treat repository content as untrusted data and bind patch paths to explicit user authorization "
            "outside the model. Reject traversal, protected paths, and forbidden command content before apply."
        )
    else:
        question = (
            "Does a mitigation reduce privileged tool calls containing attacker-controlled arguments after "
            "an agent reads an injected retrieved document, without materially reducing clean-task success?"
        )
        setup = (
            "M0 is the baseline, M1 isolates retrieved content in the prompt, and M2 enforces an external "
            "recipient-authorization policy."
        )
        proposed_control = (
            "Treat retrieved content as untrusted data and enforce privileged arguments against explicit user "
            "authorization outside the model. Prompt-level isolation and boundary enforcement make different "
            "claims and require separate evidence."
        )
    lines = [
        "# Evaluation Evidence Record",
        "",
        "## What these results do not show",
        "",
        "This study does not establish production safety or universal prompt-injection resistance. "
        "It uses synthetic inputs, hand-written attacks, mocked tools, and one model configuration. "
        + (
            "The committed reference run uses a scripted stochastic fixture to validate the evaluation software; it is not evidence about a deployed language model."
            if adapter_kind.startswith("scripted")
            else "Hosted-model results are specific to the recorded model version, prompt, provider, and run date."
        ),
        "",
        "## Question",
        "",
        question,
        "",
        "## Setup",
        "",
        f"The evidence set contains {summary['run_count']} recorded runs across clean and injected synthetic scenarios. "
        + setup,
        "",
        f"- Model: `{', '.join(metadata.get('models', ['not recorded']))}`",
        f"- Adapter: `{', '.join(metadata.get('adapters', [adapter_kind]))}`",
        f"- Temperature: `{_values(metadata.get('temperatures'))}`; effort: `{_values(metadata.get('efforts'))}`",
        f"- Harness commit: `{', '.join(metadata.get('git_shas', ['not recorded']))}`",
        f"- Recorded UTC: `{metadata.get('recorded_at_utc', {}).get('first', 'not recorded')}` to `{metadata.get('recorded_at_utc', {}).get('last', 'not recorded')}`",
        f"- API calls: `{metadata.get('api_calls', 'not recorded')}`; input tokens: `{metadata.get('input_tokens', 'not recorded')}`; output tokens: `{metadata.get('output_tokens', 'not recorded')}`",
        f"- Trace SHA-256: `{metadata.get('trace_sha256', 'not recorded')}`",
        "",
        "## Results",
        "",
        "| Config | Attempted ASR | Executed ASR | Blocked injected runs | Clean task success | Mixed injected scenarios |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for config, values in summary["configs"].items():
        lines.append(
            f"| {config} | {_pct(values['attempted_asr_injected'])} | "
            f"{_pct(values['executed_asr_injected'])} | {values['blocked_injected_runs']} | "
            f"{_pct(values['clean_task_success'])} | "
            f"{_pct(values['mixed_injected_scenarios'])} |"
        )
    lines.extend(["", "### Paired comparisons", ""])
    for name, comparison in summary["comparisons"].items():
        lines.append(f"- `{name}`: {_comparison_line(comparison)}")
    baseline_asr = summary["configs"].get("M0", {}).get("executed_asr_injected")
    lines.extend(["", "### Interpretation", ""])
    if baseline_asr == 0.0:
        upper = summary["configs"]["M0"]["zero_event_upper95_scenario_attack_rate"]
        lines.append(
            "No attacker-controlled privileged call was observed in the baseline. This floor effect means "
            "the study cannot show that M1 reduced attack success, and M2's blocking behavior was not "
            "exercised by these model-generated calls. The one-sided 95% upper bound for scenario-level "
            f"attack occurrence is {upper * 100:.1f}%. The result supports only that no attack success was "
            "observed in this synthetic suite under the recorded model configuration."
        )
    else:
        lines.append(
            "Interpret the paired estimates and confidence intervals against the preregistered security and "
            "clean-task thresholds; they apply only to the recorded scenarios and model configuration."
        )
    lines.extend(["", "### Preregistered gate", ""])
    for name, check in gate["checks"].items():
        status = check["status"] if isinstance(check, dict) else ("PASS" if check else "INCONCLUSIVE")
        lines.append(f"- {status}: `{name}`")

    lines.extend(["", "## Example traces", ""])
    for line_number in example_lines:
        lines.append(f"- [{trace_path} line {line_number}]({trace_path}#L{line_number})")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Synthetic tasks and input corpus may not represent production distributions.",
            "- Hand-written injection families provide limited attack diversity.",
            "- The primary grader detects structured tool arguments, not downstream semantic harm.",
            "- Scenario repetitions measure stochastic variation but do not add independent scenario diversity.",
            "- Per-axis breakdowns are exploratory because each cell is small.",
            "",
            "## Proposed controls",
            "",
            proposed_control,
            "",
            "## Retest triggers",
            "",
            "Retest after a model, system prompt, retrieval pipeline, tool schema, argument normalizer, authorization policy, or input-ingestion change.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_finding(
    summary: dict[str, Any],
    gate: dict[str, Any],
    trace_path: str,
    run_metadata: dict[str, Any] | None = None,
    task_domain: str = "email",
) -> dict[str, Any]:
    if task_domain == "code":
        question = "Can injected repository content cause a patch with attacker-controlled path or content?"
        path = ["synthetic_repo_file", "read_repo_file", "code_agent", "patch_policy", "mock_apply_patch"]
        controls = [
            {"id": "M1", "type": "behavioral", "description": "repository-content isolation"},
            {"id": "M2", "type": "boundary", "description": "patch path and content authorization"},
        ]
        retest_triggers = [
            "model",
            "prompt",
            "repo_reader",
            "file_corpus",
            "patch_schema",
            "patch_policy",
        ]
    else:
        question = "Can retrieved attacker instructions cause a privileged tool call with attacker-controlled arguments?"
        path = ["synthetic_document", "retrieval", "agent", "authorization_policy", "mocked_tool"]
        controls = [
            {"id": "M1", "type": "behavioral", "description": "retrieved-content isolation"},
            {"id": "M2", "type": "boundary", "description": "explicit argument authorization"},
        ]
        retest_triggers = ["model", "prompt", "retriever", "corpus", "tool_schema", "policy"]
    return {
        "schema_version": "0.1-vendor-neutral",
        "question": question,
        "path": path,
        "controls_under_test": controls,
        "result": {"summary": summary, "gate": gate},
        "run_metadata": run_metadata or {},
        "evidence": {"trace_jsonl": trace_path},
        "claims_boundary": "Synthetic scenarios and the recorded model/configuration only; not a safety certification.",
        "retest_triggers": retest_triggers,
    }


def write_report_files(
    summary: dict[str, Any],
    gate: dict[str, Any],
    destination: str | Path,
    finding_destination: str | Path,
    trace_path: str,
    example_lines: list[int],
    adapter_kind: str,
    run_metadata: dict[str, Any] | None = None,
    task_domain: str = "email",
) -> None:
    markdown_target = Path(destination)
    finding_target = Path(finding_destination)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    finding_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.write_text(
        generate_evidence_markdown(
            summary, gate, trace_path, example_lines, adapter_kind, run_metadata, task_domain
        ),
        encoding="utf-8",
    )
    finding_target.write_text(
        json.dumps(
            generate_finding(summary, gate, trace_path, run_metadata, task_domain), indent=2
        )
        + "\n",
        encoding="utf-8",
    )
