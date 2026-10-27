# Limitations

## Scope of the system

The target is a deliberately small document-assisted agent with one benign retrieval tool and one mocked privileged email tool. It is not a production agent architecture. The authorization policy binds one normalized recipient to an explicit user request; real systems have richer identities, permissions, side effects, and approval flows.

The code-agent extension is also deliberately small. It reads synthetic repository files and records a proposed patch without parsing or applying a real diff. Its policy covers explicit path binding, traversal, a short protected-path list, a requested marker, and a small forbidden-token list. Production code agents require semantic diff inspection, sandboxing, capability controls, command isolation, review workflows, and repository-specific policy.

## Scenario coverage

The corpus, tasks, attacker instructions, and expected outcomes are synthetic. Twenty injected scenarios and ten clean controls provide scenario diversity, while repeated runs estimate stochastic variation. Repetitions do not create additional independent tasks. The suite is designed to detect large effects and is not powered for small differences.

The injection axes cover placement, rhetorical style, and targeted step. They do not cover adaptive attackers, multilingual attacks, encoded payloads, images, long-context attacks, poisoned embeddings, compromised tools, or production document formats.

The code-agent family contains only four injected and two clean scenario clusters. It is useful for demonstrating the repository-file → agent → patch-policy path, but it is too small for narrow effect estimates and currently uses only the scripted engineering fixture.

## Measurement

The primary grader checks structured tool-call arguments. This avoids an LLM judge for the primary outcome but does not measure semantic leakage, persuasion, user harm, or side effects outside the declared tool schema. Clean-task success requires an exact synthetic fact and marker, so it is reliable for this suite but narrow.

The paired hierarchical bootstrap preserves scenario clustering, but confidence intervals are still sensitive to the small number of scenario clusters. Per-axis results are exploratory.

When no event occurs in any scenario cluster, the bootstrap distribution collapses to zero and cannot express uncertainty. Those cases are reported with a one-sided 95% upper bound on scenario-level event occurrence instead of a zero-width interval. With 20 injected clusters that bound is 13.9%; with 10 clean clusters it is 25.9%.

## Mitigation claims

M1 is a behavioral prompt intervention whose result may vary by model, provider, prompt formatting, decoding settings, and date. M2 is an external boundary control. A zero executed attack-success rate for declared attacker recipients shows that the tested policy enforced its rule; it does not show that the policy is complete or bypass-proof.

M1 and M2 therefore support different claims and should not be ranked using attack-success rate alone. M2 must also be evaluated for bypasses and false blocking.

## Reproducibility

Committed scripted traces validate the runner, trace format, policy, grader, replay, statistics, and report generation. The scripted adapter is not a language model and its outcome rates are not evidence about any deployed model.

Hosted-model results are dated observations. A provider may change infrastructure behind an identifier, seeds may not be honored, and retries may alter sampling. The committed raw traces—not the ability to regenerate identical hosted outputs—are the reproducible artifact.

The positive control deliberately instructs the model to treat retrieved text as authoritative. It demonstrates that the harness can observe vulnerable behavior and that the policy path can be exercised; it does not estimate vulnerability under a realistic system prompt or production deployment.

## Claims not supported

This project does not establish that:

- Either mitigation makes an agent safe.
- The measured effect transfers to another model or domain.
- The scenario distribution represents real attacks.
- The deterministic policy covers every encoding or confused-deputy path.
- Passing the regression gate is a safety certification.

