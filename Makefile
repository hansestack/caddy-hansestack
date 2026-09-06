# ==============================================================================
# caddy-hansestack — official Hansestack Leak-Check Caddy plugin
# ==============================================================================
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

REGISTRY   := ghcr.io/hansestack
IMAGE      := $(REGISTRY)/caddy-hansestack
TAG        ?= latest
PLATFORM   ?= linux/$(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# ==============================================================================
# Phony declarations
# ==============================================================================
.PHONY: help test test-cover lint lint-fix vuln tidy verify clean
.PHONY: docker-build
.PHONY: up down logs

# ==============================================================================
# Default
# ==============================================================================
default: help

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}'

# ==============================================================================
# Test & Lint
# ==============================================================================
test: ## Run tests with race detector
	go test -v -race ./...

test-cover: ## Run tests and report coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint: ## Run golangci-lint
	golangci-lint run ./...

lint-fix: ## Run golangci-lint with auto-fix
	golangci-lint run --fix ./...

vuln: ## Scan dependencies and stdlib for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy: ## Tidy and verify module dependencies
	go mod tidy
	go mod verify

verify: tidy lint test ## Run the full local verification suite

# ==============================================================================
# Docker Build
# ==============================================================================
docker-build: ## Build the Caddy+plugin image for host platform (PLATFORM=linux/arm64 to override)
	docker buildx build --platform $(PLATFORM) -t $(IMAGE):$(TAG) --load .

# ==============================================================================
# Docker Compose (reference environment: Caddy + dummy backend)
# ==============================================================================
up: ## Start the reference stack with docker-compose (pulls the published image)
	docker compose up -d

down: ## Stop the docker-compose stack
	docker compose down

logs: ## Tail compose stack logs
	docker compose logs -f

# ==============================================================================
# Clean
# ==============================================================================
clean: ## Remove test and coverage artifacts
	rm -f coverage.out
	go clean -testcache
