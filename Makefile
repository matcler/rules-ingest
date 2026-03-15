PYTHON ?= python3
VENV_PYTHON := .venv/bin/python
PYTHON_BIN := $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(PYTHON))

.PHONY: gate-baseline gate-baseline-ci install-hooks

gate-baseline:
	$(PYTHON_BIN) -m py_compile tools/validate_json.py
	$(PYTHON_BIN) tools/validate_json.py --baseline
	$(PYTHON_BIN) tools/validate_json.py --atoms ingest/atoms/combat.mvp.atoms.json dist
	$(PYTHON_BIN) tools/validate_json.py --rules

gate-baseline-ci: gate-baseline

install-hooks:
	git config core.hooksPath .githooks
