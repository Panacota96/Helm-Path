SHELL := /bin/bash

PYTHON ?= python

.PHONY: install dev-install test compile smoke ci build-lite build-full clean

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install .

dev-install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

compile:
	$(PYTHON) -m compileall helm_path Test

smoke:
	$(PYTHON) -m helm_path.main --help

ci: compile test smoke

build-lite:
	docker build -t helm-path:lite -f docker/Dockerfile.lite .

build-full:
	docker build -t helm-path:kali -f docker/Dockerfile.kali .

clean:
	rm -rf build dist *.egg-info .pytest_cache
