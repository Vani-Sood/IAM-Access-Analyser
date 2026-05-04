# IAM Policy Analyzer — Developer Makefile
# Usage: make help

.PHONY: setup up down test test-frontend logs lint help

help:          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

setup:         ## Bootstrap: copy .env, generate JWT_SECRET
	@bash scripts/setup.sh

up:            ## Build and start all services
	docker compose up -d --build

down:          ## Stop all services
	docker compose down

test:          ## Run backend tests (requires running stack)
	docker compose exec backend pytest -v

test-frontend: ## Run frontend Jest tests (local node_modules)
	cd frontend && npm test

logs:          ## Tail all service logs
	docker compose logs -f --tail=100

lint:          ## Lint backend (ruff + black check)
	docker compose exec backend ruff check . && docker compose exec backend black --check .
