# PYTHON is the interpreter everything runs through. The console scripts pip
# installs bind to whichever interpreter installed them, which on a machine with
# several Pythons is not necessarily the one on PATH. Running modules through an
# explicit interpreter removes that class of "works for me" report.
# Override with: make verify PYTHON=python3.12
PYTHON ?= python3

.PHONY: install verify test lint demo report bench image clean

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src tests tools benchmark scripts

test:
	$(PYTHON) -m pytest --cov=ibr --cov-report=term-missing --cov-report=xml

# Runs every check CI runs, in the same order, so a green local verify means a
# green build. A verify that is a subset of CI is a verify that lies.
verify: lint test
	$(PYTHON) tools/check_dependencies.py
	$(PYTHON) tools/check_contrast.py
	$(PYTHON) scripts/provenance_check.py

demo:
	$(PYTHON) -m ibr.cli generate --principals 2000 --out data/generated/account.json --seed 7
	$(PYTHON) -m ibr.cli analyse --account data/generated/account.json \
		--out docs/report.html --json docs/reachability.json

report:
	$(PYTHON) tools/collect_metrics.py

bench:
	$(PYTHON) benchmark/run_benchmark.py

image:
	docker build -t iam-blast-radius:local .

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage data/generated
