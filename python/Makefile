.PHONY: lint test build

PYTHON ?= python3

lint:
	$(PYTHON) -m ruff check src tests examples
	$(PYTHON) -m ruff format --check src tests examples
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest

build:
	$(PYTHON) -m build
