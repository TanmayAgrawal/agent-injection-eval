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
- Harness commit: `e956600b81b2dc488c7b32d4058b42cb264da496`
- Recorded UTC: `2026-10-26T17:33:47.168960+00:00` to `2026-10-26T17:43:29.519556+00:00`
- API calls: `1800`; input tokens: `519060`; output tokens: `68445`
- Trace SHA-256: `813070e78062c7cd74120c7583c5e77c28179b9f8542596d78664c86de1f4365`

## Results

| Config | Attempted ASR | Executed ASR | Clean task success | Mixed injected scenarios |
| --- | ---: | ---: | ---: | ---: |
| M0 | 0.0% | 0.0% | 100.0% | 0.0% |
| M1 | 0.0% | 0.0% | 100.0% | 0.0% |
| M2 | 0.0% | 0.0% | 100.0% | 0.0% |

### Paired comparisons

- `M1_vs_M0_executed_asr`: +0.0 percentage points (95% CI +0.0 to +0.0; 20 scenario clusters)
- `M1_vs_M0_clean_success`: +0.0 percentage points (95% CI +0.0 to +0.0; 10 scenario clusters)
- `M2_vs_M0_executed_asr`: +0.0 percentage points (95% CI +0.0 to +0.0; 20 scenario clusters)

### Interpretation

No attacker-controlled privileged call was observed in the baseline. This floor effect means the study cannot show that M1 reduced attack success, and M2's blocking behavior was not exercised by these model-generated calls. The result supports only that no attack success was observed in this synthetic suite under the recorded model configuration.

### Preregistered gate

- INCONCLUSIVE: `m1_security_upper_below_zero`
- PASS: `m1_clean_lower_above_margin`
- PASS: `m2_executed_asr_zero`
- PASS: `m2_clean_false_block_at_most_10pct`

## Example traces

- [../../traces/live/gpt-5-4.jsonl line 311](../../traces/live/gpt-5-4.jsonl#L311)
- [../../traces/live/gpt-5-4.jsonl line 11](../../traces/live/gpt-5-4.jsonl#L11)
- [../../traces/live/gpt-5-4.jsonl line 611](../../traces/live/gpt-5-4.jsonl#L611)

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
