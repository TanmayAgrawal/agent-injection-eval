PYTHON ?= python3
PYTHONPATH := src
TRACE := traces/reference-scripted.jsonl
CLAUDE_TRACE := traces/live/claude-sonnet-5-5.jsonl
OPENAI_TRACE := traces/live/gpt-5-4.jsonl

.PHONY: test validate record-reference record-claude record-openai reproduce report report-claude report-openai gate gate-claude gate-openai clean-generated

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover -s tests -v

validate:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m compileall -q src tests scripts
	git diff --check

record-reference:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli record-suite \
		--config configs/M0.json \
		--config configs/M1.json \
		--config configs/M2.json \
		--repetitions 10 \
		--adapter scripted \
		--output $(TRACE)

record-claude:
	@test -n "$$ANTHROPIC_API_KEY" || (echo "ANTHROPIC_API_KEY is not set" && exit 1)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli record-suite \
		--config configs/M0-claude-sonnet-5-5.json \
		--config configs/M1-claude-sonnet-5-5.json \
		--config configs/M2-claude-sonnet-5-5.json \
		--repetitions 10 \
		--adapter anthropic \
		--output $(CLAUDE_TRACE)

record-openai:
	@test -n "$$OPENAI_API_KEY" || (echo "OPENAI_API_KEY is not set" && exit 1)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli record-suite \
		--config configs/M0-gpt-5-4.json \
		--config configs/M1-gpt-5-4.json \
		--config configs/M2-gpt-5-4.json \
		--repetitions 10 \
		--workers 8 \
		--adapter openai \
		--output $(OPENAI_TRACE)

report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli stats \
		--input $(TRACE) \
		--output reports/summary.json > /dev/null
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli report \
		--input $(TRACE) \
		--output reports/EVIDENCE.md \
		--finding reports/finding.json

report-claude:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli stats \
		--input $(CLAUDE_TRACE) \
		--output reports/generated/claude-summary.json > /dev/null
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli report \
		--input $(CLAUDE_TRACE) \
		--output reports/generated/CLAUDE-EVIDENCE.md \
		--finding reports/generated/claude-finding.json

report-openai:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli stats \
		--input $(OPENAI_TRACE) \
		--output reports/generated/openai-summary.json > /dev/null
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli report \
		--input $(OPENAI_TRACE) \
		--output reports/generated/OPENAI-EVIDENCE.md \
		--finding reports/generated/openai-finding.json

gate:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli gate --input $(TRACE)

gate-claude:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli gate --input $(CLAUDE_TRACE)

gate-openai:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli gate --input $(OPENAI_TRACE)

reproduce: test
	mkdir -p .eval-tmp
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli replay \
		--input $(TRACE) \
		--output .eval-tmp/replayed.jsonl
	$(MAKE) report
	$(MAKE) gate

clean-generated:
	@echo "Generated scratch files are kept under .eval-tmp/ and ignored by git."

