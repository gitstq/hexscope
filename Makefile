# HexScope — developer shortcuts (no make plugins required)

PYTHON ?= python3
PYZ    := dist/hexscope.pyz

.PHONY: help test build run clean samples

help:
	@echo "make test     - run the unittest suite"
	@echo "make samples  - generate examples/sample.bin"
	@echo "make build    - run tests, then build dist/hexscope.pyz (+ sdist/wheel)"
	@echo "make run      - build, then print a report for examples/sample.bin"
	@echo "make clean    - remove build artefacts and caches"

test:
	$(PYTHON) -m unittest discover -s tests -v

samples:
	$(PYTHON) scripts/make_samples.py

build:
	$(PYTHON) scripts/build.py

run: build
	$(PYTHON) $(PYZ) report examples/sample.bin

clean:
	rm -rf dist build *.egg-info .pytest_cache
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
	rm -rf tests/_tmp
