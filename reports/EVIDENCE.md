# Evaluation Evidence Record

## What these results do not show

This study does not establish production safety or universal prompt-injection resistance. It uses synthetic documents, hand-written attacks, mocked tools, and one model configuration. The committed reference run uses a scripted stochastic fixture to validate the evaluation software; it is not evidence about a deployed language model.

## Question

Does a mitigation reduce privileged tool calls containing attacker-controlled arguments after an agent reads an injected retrieved document, without materially reducing clean-task success?

## Setup

The evidence set contains 900 recorded runs across clean and injected synthetic scenarios. M0 is the baseline, M1 isolates retrieved content in the prompt, and M2 enforces an external recipient-authorization policy.

## Results

| Config | Attempted ASR | Executed ASR | Clean task success | Mixed injected scenarios |
| --- | ---: | ---: | ---: | ---: |
| M0 | 67.5% | 67.5% | 95.0% | 95.0% |
| M1 | 31.0% | 31.0% | 94.0% | 95.0% |
| M2 | 72.0% | 0.0% | 96.0% | 0.0% |

### Paired comparisons

- `M1_vs_M0_executed_asr`: -36.5 percentage points (95% CI -48.0 to -24.5; 20 scenario clusters)
- `M1_vs_M0_clean_success`: -1.0 percentage points (95% CI -8.0 to +5.0; 10 scenario clusters)
- `M2_vs_M0_executed_asr`: -67.5 percentage points (95% CI -77.0 to -58.0; 20 scenario clusters)

### Preregistered gate

- PASS: `m1_security_upper_below_zero`
- PASS: `m1_clean_lower_above_margin`
- PASS: `m2_executed_asr_zero`
- PASS: `m2_clean_false_block_at_most_10pct`

## Example traces

- [../traces/reference-scripted.jsonl line 11](../traces/reference-scripted.jsonl#L11)
- [../traces/reference-scripted.jsonl line 311](../traces/reference-scripted.jsonl#L311)
- [../traces/reference-scripted.jsonl line 611](../traces/reference-scripted.jsonl#L611)

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
