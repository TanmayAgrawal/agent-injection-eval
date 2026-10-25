PYTHON ?= python3
PYTHONPATH := src
TRACE := traces/reference-scripted.jsonl

.PHONY: test validate record-reference reproduce report gate clean-generated

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

report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli report \
		--input $(TRACE) \
		--output reports/EVIDENCE.md \
		--finding reports/finding.json

gate:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli gate --input $(TRACE)

reproduce: test
	mkdir -p .eval-tmp
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m agent_eval.cli replay \
		--input $(TRACE) \
		--output .eval-tmp/replayed.jsonl
	$(MAKE) report
	$(MAKE) gate

clean-generated:
	@echo "Generated scratch files are kept under .eval-tmp/ and ignored by git."

