.DEFAULT_GOAL := help
.PHONY: help install test test-cov lint fmt fmt-check typecheck migrate \
	dev-up dev-down dev-logs dev-status smoke check

BACKEND := backend

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install/sync backend Python dependencies
	cd $(BACKEND) && uv sync

test: ## Run the backend test suite
	cd $(BACKEND) && uv run pytest

test-cov: ## Run the backend test suite with coverage report
	cd $(BACKEND) && uv run pytest --cov

lint: ## Run ruff lint checks, including the static security analysis
	cd $(BACKEND) && uv run ruff check .

fmt: ## Format backend code with ruff
	cd $(BACKEND) && uv run ruff format .

fmt-check: ## Check backend code formatting without modifying files
	cd $(BACKEND) && uv run ruff format --check .

typecheck: ## Run mypy strict type checking
	cd $(BACKEND) && uv run mypy .

migrate: ## Apply database migrations (alembic upgrade head)
	cd $(BACKEND) && uv run alembic upgrade head

dev-up: ## Start local dev infrastructure (PostgreSQL + Redis)
	./scripts/dev-env.sh up

dev-down: ## Stop local dev infrastructure
	./scripts/dev-env.sh down

dev-logs: ## Follow local dev infrastructure logs
	./scripts/dev-env.sh logs

dev-status: ## Show local dev infrastructure status
	./scripts/dev-env.sh status

smoke: ## Run the Docker Compose image smoke test suite
	./scripts/image-smoke.sh

check: lint fmt-check typecheck test ## Run the full pre-submission checklist (lint, format, typecheck, test)
