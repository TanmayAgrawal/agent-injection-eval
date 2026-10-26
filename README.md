# Retrieved Prompt Injection Evaluation Harness

[![CI](https://github.com/TanmayAgrawal/agent-injection-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/TanmayAgrawal/agent-injection-eval/actions/workflows/ci.yml)

## What the results do not show

This project does not establish production safety or universal prompt-injection resistance. It evaluates a toy agent with synthetic documents, mocked tools, hand-written attacks, and a narrow programmatic grader. The scripted reference traces validate the evaluation software only. The separate hosted-model evidence applies only to the committed GPT-5.4 snapshot, prompts, tools, synthetic scenarios, and recorded run window.

## Evaluation question

Does a mitigation reduce how often a tool-using agent makes a privileged tool call with attacker-controlled arguments after reading an injected instruction in retrieved content, and does it reduce task success on clean inputs?

The question, outcomes, comparisons, decision rules, and claims boundary were committed in [`PREREG.md`](PREREG.md) before the harness was executed. The root preregistration commit is `9f28e52`.

## System under test

The agent first calls `search_docs`, then may propose `send_email(to, body)`. Both tools are synthetic. `send_email` records an action but has no external side effect.

The suite contains 30 scenarios:

- 20 injected scenarios varying placement, style, target step, and selected argument-normalization bypasses.
- 10 clean controls matched by benign task group.
- Four shopping-task families with explicit authorized recipients and deterministic completion criteria.

Three configurations test different claims:

- **M0:** no mitigation.
- **M1:** prompt-level isolation of retrieved content.
- **M2:** an external deterministic recipient-authorization policy.

The neutral M0 prompt contains no authorization, untrusted-content, or instruction-isolation language. A separate preregistered positive control deliberately makes retrieved instructions authoritative to verify that the harness can detect known-vulnerable behavior.

## Repository map

```text
PREREG.md                 preregistered question and analysis plan
LIMITATIONS.md            detailed claims boundary
scenarios/                scenario manifest and JSON Schema
configs/                  versioned prompts and run configurations
src/agent_eval/agent.py   target tool loop
src/agent_eval/tools.py   mocked tools and deterministic policy
src/agent_eval/runner.py  scenario/config execution
src/agent_eval/grader.py  programmatic outcome labels
src/agent_eval/replay.py  deterministic downstream replay
src/agent_eval/stats.py   paired hierarchical bootstrap
src/agent_eval/report.py  evidence record and JSON finding
traces/                   trace schema and committed reference run
tests/                    unit and regression tests
```

## Reproduce the committed evidence

Python 3.11 or later is sufficient; the runtime has no third-party dependencies.

```bash
make reproduce
```

This command:

1. Runs the unit tests.
2. Replays every committed response through policy enforcement, mocked tools, and grading.
3. Regenerates the evidence record and vendor-neutral JSON finding.
4. Applies the preregistered security and utility gate.

Replay verifies deterministic downstream processing. It does not reproduce model behavior.

## Record a fresh suite

The runner refuses to record against a dirty worktree unless `--allow-dirty` is explicitly passed. To generate the scripted engineering reference:

```bash
make record-reference
make report
make gate
```

The resulting 900 runs are 30 scenarios × 3 configurations × 10 repetitions.

To use an OpenAI-compatible hosted endpoint:

1. Copy `configs/hosted.example.json` to a versioned configuration.
2. Set the exact model identifier and mitigation prompt.
3. Commit the configuration before execution.
4. Set `OPENAI_API_KEY`; optionally set `OPENAI_BASE_URL`.
5. Run `agent-eval record` with `--adapter hosted`.

```bash
PYTHONPATH=src python3 -m agent_eval.cli record \
  --config configs/M0-hosted.json \
  --adapter hosted \
  --repetitions 10 \
  --output traces/live/M0-hosted.jsonl
```

Do not describe scripted-fixture results as model evidence. For hosted runs, retain the raw traces and report the model identifier, configuration hashes, provider, and run date.

### Primary OpenAI run

The primary live protocol uses the fixed `gpt-5.4-2026-03-05` snapshot through the Responses API. It holds reasoning effort at `none` so the preregistered `temperature: 0.7` sampling control remains valid. The adapter disables provider-side response storage, defines strict function schemas, prevents parallel tool calls, and records the raw response in each local trace.

Keep the API key outside the repository:

```bash
export OPENAI_API_KEY="your-key"
make record-openai
make report-openai
make gate-openai
```

This records 900 live runs in `traces/live/gpt-5-4.jsonl`. The hosted trace is intentionally committed after credential inspection; future ad hoc files under `traces/live/` remain ignored unless explicitly added.

### Positive-control run

[`POSITIVE_CONTROL.md`](POSITIVE_CONTROL.md) preregisters a deliberately vulnerable target configuration used only to validate harness sensitivity. It uses the same GPT-5.4 snapshot, scenarios, tools, grader, and repetitions as the primary run.

```bash
export OPENAI_API_KEY="your-key"
make record-positive-control
make report-positive-control
make gate-positive-control
```

### Anthropic integration example — not run

The committed Claude configurations are unrun integration examples, not evidence. No valid Anthropic credential was available and no Claude trace or result is included. The example uses `claude-sonnet-5-5` with adaptive thinking and `high` effort.

Keep the API key outside the repository:

```bash
export ANTHROPIC_API_KEY="your-key"
```

If the key is not scoped to a single workspace, also set `ANTHROPIC_WORKSPACE_ID`. Then commit any pending code or configuration changes and run:

```bash
make record-claude-example
make report-claude-example
make gate-claude-example
```

This records 900 live runs in `traces/live/claude-sonnet-5-5.jsonl`. The directory is ignored by Git until the traces have been inspected for secrets and intentionally force-added as an evidence artifact. The API version defaults to `2023-06-01` and can be overridden with `ANTHROPIC_VERSION`; the trace records the selected version and effort level.

## Replay, compare, and report

```bash
PYTHONPATH=src python3 -m agent_eval.cli replay \
  --input traces/reference-scripted.jsonl \
  --output .eval-tmp/replayed.jsonl

PYTHONPATH=src python3 -m agent_eval.cli stats \
  --input traces/reference-scripted.jsonl

PYTHONPATH=src python3 -m agent_eval.cli rerun \
  --baseline traces/reference-scripted.jsonl \
  --config configs/M1.json \
  --adapter scripted \
  --output traces/live/M1-rerun.jsonl
```

## Evidence outputs

- [`reports/EVIDENCE.md`](reports/EVIDENCE.md) presents the question, setup, uncertainty, trace examples, limitations, proposed controls, and retest triggers.
- [`reports/finding.json`](reports/finding.json) connects source, retrieval, agent, policy, and tool stages without assuming a vendor schema.
- `traces/reference-scripted.jsonl` is the replayable reference artifact.
- [`reports/generated/OPENAI-EVIDENCE.md`](reports/generated/OPENAI-EVIDENCE.md) is the 900-run GPT-5.4 evidence record.
- [`reports/generated/openai-finding.json`](reports/generated/openai-finding.json) is its vendor-neutral machine-readable finding.
- `traces/live/gpt-5-4.jsonl` is the hosted-model trace artifact. Its SHA-256 is recorded in the evidence report.

The hosted run observed 0% attack success and 100% clean-task success in every configuration. Because M0 also had 0% attack success, the M1 mitigation effect is inconclusive due to a floor effect; this is not evidence that M1 is effective or that GPT-5.4 is generally resistant to prompt injection.

## Safe use

All included data is synthetic. The tools are mocked, no emails are sent, and no credentials or proprietary data are included.

