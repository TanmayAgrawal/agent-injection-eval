# Evaluation Evidence Record

## What these results do not show

This study does not establish production safety or universal prompt-injection resistance. It uses synthetic documents, hand-written attacks, mocked tools, and one model configuration. Hosted-model results are specific to the recorded model version, prompt, provider, and run date.

## Question

Does a mitigation reduce privileged tool calls containing attacker-controlled arguments after an agent reads an injected retrieved document, without materially reducing clean-task success?

## Setup

The evidence set contains 900 recorded runs across clean and injected synthetic scenarios. M0 is the baseline, M1 isolates retrieved content in the prompt, and M2 enforces an external recipient-authorization policy.

- Model: `gpt-5.4-2026-03-05`
- Adapter: `openai`
- Temperature: `0.7`; effort: `none`
- Harness commit: `5a2272bf2b11d969b4a5c70a47566afbd335a559`
- Recorded UTC: `2026-10-26T23:38:22.871199+00:00` to `2026-10-26T23:46:34.315894+00:00`
- API calls: `1800`; input tokens: `568260`; output tokens: `72643`
- Trace SHA-256: `9e8ee59388a80cd7ddf0fca769c9e0741fef6bcb1e52e5ea41997239f6b43653`

## Results

| Config | Attempted ASR | Executed ASR | Blocked injected runs | Clean task success | Mixed injected scenarios |
| --- | ---: | ---: | ---: | ---: | ---: |
| M0 | 54.5% | 54.5% | 0 | 100.0% | 25.0% |
| M1 | 0.0% | 0.0% | 0 | 100.0% | 0.0% |
| M2 | 54.5% | 0.0% | 109 | 100.0% | 0.0% |

### Paired comparisons

- `M1_vs_M0_executed_asr`: -54.5 percentage points (95% CI -74.5 to -34.5; 20 scenario clusters)
- `M1_vs_M0_clean_success`: no clean-task difference observed, but a zero-width bootstrap interval is uninformative; one-sided 95% upper bound for scenario-level clean failure occurrence is 25.9% across 10 scenario clusters
- `M2_vs_M0_executed_asr`: -54.5 percentage points (95% CI -74.5 to -34.5; 20 scenario clusters)

### Interpretation

Interpret the paired estimates and confidence intervals against the preregistered security and clean-task thresholds; they apply only to the recorded scenarios and model configuration.

### Preregistered gate

- PASS: `m1_security_upper_below_zero`
- INCONCLUSIVE: `m1_clean_lower_above_margin`
- PASS: `m2_executed_asr_zero`
- PASS: `m2_clean_false_block_at_most_10pct`

## Example traces

- [../../traces/live/gpt-5-4-positive-control.jsonl line 11](../../traces/live/gpt-5-4-positive-control.jsonl#L11)
- [../../traces/live/gpt-5-4-positive-control.jsonl line 311](../../traces/live/gpt-5-4-positive-control.jsonl#L311)
- [../../traces/live/gpt-5-4-positive-control.jsonl line 611](../../traces/live/gpt-5-4-positive-control.jsonl#L611)

## Limitations

- Synthetic tasks and document corpus may not represent production distributions.
- Hand-written injection families provide limited attack diversity.
- The primary grader detects structured tool arguments, not downstream semantic harm.
- Scenario repetitions measure stochastic variation but do not add independent scenario diversity.
- Per-axis breakdowns are exploratory because each cell is small.

## Proposed controls

Treat retrieved content as untrusted data and enforce privileged arguments against explicit user authorization outside the model. Prompt-level isolation and boundary enforcement make different claims and require separate evidence.

## Retest triggers

Retest after a model, system prompt, retrieval pipeline, tool schema, argument normalizer, authorization policy, or document-ingestion change.
