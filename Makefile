.DEFAULT_GOAL := help
SHELL := /bin/bash

DIST := dist
AGENT_VERSION := $(shell grep '^version' agent/Cargo.toml | head -1 | cut -d'"' -f2)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- agent

.PHONY: test
test: agent-test ## Run all tests

.PHONY: agent-test
agent-test: ## Run agent tests (host-native)
	cd agent && cargo test

.PHONY: agent-lint
agent-lint: ## Clippy + rustfmt check
	cd agent && cargo clippy --all-targets -- -D warnings
	cd agent && cargo fmt --check

$(DIST):
	mkdir -p $(DIST)

.PHONY: agent-image-armv7
agent-image-armv7: | $(DIST) ## Build armv7 image and export a RouterOS-importable tar
	docker buildx build --platform linux/arm/v7 --output=type=docker \
	    --provenance=false --sbom=false \
	    --build-arg TARGET=armv7-unknown-linux-musleabihf \
	    -t mqagent:$(AGENT_VERSION)-armv7 agent/
	docker save mqagent:$(AGENT_VERSION)-armv7 -o $(DIST)/mqagent-$(AGENT_VERSION)-armv7.tar
	python3 deploy/mikrotik/oci-to-docker-archive.py \
	    $(DIST)/mqagent-$(AGENT_VERSION)-armv7.tar \
	    $(DIST)/mqagent-$(AGENT_VERSION)-armv7-ros.tar \
	    mqagent:$(AGENT_VERSION)-armv7
	@echo "-> import this one onto RouterOS: $(DIST)/mqagent-$(AGENT_VERSION)-armv7-ros.tar"

.PHONY: agent-image-arm64
agent-image-arm64: | $(DIST) ## Build arm64 image and export a RouterOS-importable tar
	docker buildx build --platform linux/arm64 --output=type=docker \
	    --provenance=false --sbom=false \
	    --build-arg TARGET=aarch64-unknown-linux-musl \
	    -t mqagent:$(AGENT_VERSION)-arm64 agent/
	docker save mqagent:$(AGENT_VERSION)-arm64 -o $(DIST)/mqagent-$(AGENT_VERSION)-arm64.tar
	python3 deploy/mikrotik/oci-to-docker-archive.py \
	    $(DIST)/mqagent-$(AGENT_VERSION)-arm64.tar \
	    $(DIST)/mqagent-$(AGENT_VERSION)-arm64-ros.tar \
	    mqagent:$(AGENT_VERSION)-arm64
	@echo "-> import this one onto RouterOS: $(DIST)/mqagent-$(AGENT_VERSION)-arm64-ros.tar"

# `docker save` (OCI archive), not `docker export` (flat rootfs) — RouterOS
# needs the manifest and layers. `--output=type=docker` above is equally
# load-bearing: BuildKit's default OCI layout has failed to import.

# ---------------------------------------------------------------- server

.PHONY: server-up
server-up: ## Start controller + TimescaleDB locally
	docker compose -f deploy/docker-compose.yml up -d --build
	@echo "controller: http://localhost:8080"

.PHONY: server-down
server-down: ## Stop the local stack
	docker compose -f deploy/docker-compose.yml down

.PHONY: server-logs
server-logs: ## Tail controller logs
	docker compose -f deploy/docker-compose.yml logs -f controller

.PHONY: server-test
server-test: ## Run controller tests in Docker (no local Go needed)
	docker run --rm -v "$$PWD/server":/src -w /src golang:1.23 go test ./...

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST)
	cd agent && cargo clean
