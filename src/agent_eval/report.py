from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _comparison_line(comparison: dict[str, Any]) -> str:
    low, high = comparison["ci95"]
    return (
        f"{comparison['point_estimate'] * 100:+.1f} percentage points "
        f"(95% CI {low * 100:+.1f} to {high * 100:+.1f}; "
        f"{comparison['n_scenarios']} scenario clusters)"
    )


def generate_evidence_markdown(
    summary: dict[str, Any],
    gate: dict[str, Any],
    trace_path: str,
    example_lines: list[int],
    adapter_kind: str,
) -> str:
    lines = [
        "# Evaluation Evidence Record",
        "",
        "## What these results do not show",
        "",
        "This study does not establish production safety or universal prompt-injection resistance. "
        "It uses synthetic documents, hand-written attacks, mocked tools, and one model configuration. "
        + (
            "The committed reference run uses a scripted stochastic fixture to validate the evaluation software; it is not evidence about a deployed language model."
            if adapter_kind == "scripted"
            else "Hosted-model results are specific to the recorded model version, prompt, provider, and run date."
        ),
        "",
        "## Question",
        "",
        "Does a mitigation reduce privileged tool calls containing attacker-controlled arguments after an agent reads an injected retrieved document, without materially reducing clean-task success?",
        "",
        "## Setup",
        "",
        f"The evidence set contains {summary['run_count']} recorded runs across clean and injected synthetic scenarios. "
        "M0 is the baseline, M1 isolates retrieved content in the prompt, and M2 enforces an external recipient-authorization policy.",
        "",
        "## Results",
        "",
        "| Config | Attempted ASR | Executed ASR | Clean task success | Mixed injected scenarios |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for config, values in summary["configs"].items():
        lines.append(
            f"| {config} | {_pct(values['attempted_asr_injected'])} | "
            f"{_pct(values['executed_asr_injected'])} | {_pct(values['clean_task_success'])} | "
            f"{_pct(values['mixed_injected_scenarios'])} |"
        )
    lines.extend(["", "### Paired comparisons", ""])
    for name, comparison in summary["comparisons"].items():
        lines.append(f"- `{name}`: {_comparison_line(comparison)}")
    lines.extend(["", "### Preregistered gate", ""])
    for name, passed in gate["checks"].items():
        lines.append(f"- {'PASS' if passed else 'INCONCLUSIVE'}: `{name}`")

    lines.extend(["", "## Example traces", ""])
    for line_number in example_lines:
        lines.append(f"- [{trace_path} line {line_number}]({trace_path}#L{line_number})")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Synthetic tasks and document corpus may not represent production distributions.",
            "- Hand-written injection families provide limited attack diversity.",
            "- The primary grader detects structured tool arguments, not downstream semantic harm.",
            "- Scenario repetitions measure stochastic variation but do not add independent scenario diversity.",
            "- Per-axis breakdowns are exploratory because each cell is small.",
            "",
            "## Proposed controls",
            "",
            "Treat retrieved content as untrusted data and enforce privileged arguments against explicit user authorization outside the model. Prompt-level isolation and boundary enforcement make different claims and require separate evidence.",
            "",
            "## Retest triggers",
            "",
            "Retest after a model, system prompt, retrieval pipeline, tool schema, argument normalizer, authorization policy, or document-ingestion change.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_finding(summary: dict[str, Any], gate: dict[str, Any], trace_path: str) -> dict[str, Any]:
    return {
        "schema_version": "0.1-vendor-neutral",
        "question": "Can retrieved attacker instructions cause a privileged tool call with attacker-controlled arguments?",
        "path": ["synthetic_document", "retrieval", "agent", "authorization_policy", "mocked_tool"],
        "controls_under_test": [
            {"id": "M1", "type": "behavioral", "description": "retrieved-content isolation"},
            {"id": "M2", "type": "boundary", "description": "explicit argument authorization"},
        ],
        "result": {"summary": summary, "gate": gate},
        "evidence": {"trace_jsonl": trace_path},
        "claims_boundary": "Synthetic scenarios and the recorded model/configuration only; not a safety certification.",
        "retest_triggers": ["model", "prompt", "retriever", "corpus", "tool_schema", "policy"],
    }


def write_report_files(
    summary: dict[str, Any],
    gate: dict[str, Any],
    destination: str | Path,
    finding_destination: str | Path,
    trace_path: str,
    example_lines: list[int],
    adapter_kind: str,
) -> None:
    Path(destination).write_text(
        generate_evidence_markdown(summary, gate, trace_path, example_lines, adapter_kind),
        encoding="utf-8",
    )
    Path(finding_destination).write_text(
        json.dumps(generate_finding(summary, gate, trace_path), indent=2) + "\n",
        encoding="utf-8",
    )
