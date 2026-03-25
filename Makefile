PYTHON ?= python3
VERSION := $(shell $(PYTHON) -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])' 2>/dev/null || echo "0.0.0")
IMAGE ?= log-anonymizer:$(VERSION)

.PHONY: help clean build install-dev run-cli run-ui smoke-test docker-build docker-smoke release-build

help:
	@echo "Targets: build clean install-dev run-cli run-ui smoke-test docker-build docker-smoke release-build"
	@echo "Examples:"
	@echo "  make build"
	@echo "  make install-dev"
	@echo "  make run-cli ARGS='--help'"
	@echo "  make release-build"

clean:
	rm -rf dist build *.egg-info src/*.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage .coverage.*
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +

build:
	$(PYTHON) -m pip install -U build
	$(PYTHON) -m build --no-isolation

install-dev:
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e ".[dev,ui]"

run-cli:
	log-anonymizer $(ARGS)

run-ui:
	log-anonymizer-ui $(ARGS)

smoke-test:
	bash ./scripts/smoke_test_wheel.sh

docker-build:
	docker build -t "$(IMAGE)" .

docker-smoke:
	IMAGE_TAG="$(IMAGE)" WITH_UI=1 bash ./scripts/smoke_test_docker.sh

release-build: clean build smoke-test docker-smoke
