# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# CertPing monorepo task runner.
#
# A thin wrapper over each app's own tooling (pnpm for apps/web, Maven for the
# Java apps). CI calls these same targets, so a green `make ci` locally means the
# same commands that gate pull requests have passed.
#
#   make help          list targets
#   make setup         install dependencies for every app
#   make ci            everything CI runs: lint, typecheck, test, build
#   make <app>-ci      the same for one app: web, server, agent, notifier

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

JAVA_APPS := server agent notifier
MVN       ?= mvn -B -ntp
PNPM      ?= pnpm
WEB       := apps/web

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z0-9_%-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo "  {server,agent,notifier}-{setup,test,build,ci}  the same per Java app"

# ── Aggregates ───────────────────────────────────────────────────────────────

.PHONY: setup lint test build ci
setup: web-setup $(addsuffix -setup,$(JAVA_APPS)) ## Install dependencies for every app
lint: web-lint helm-lint ## Lint and typecheck every app
test: web-test $(addsuffix -test,$(JAVA_APPS)) ## Unit and integration tests for every app
build: web-build $(addsuffix -build,$(JAVA_APPS)) ## Build every app
ci: license-headers-check web-ci $(addsuffix -ci,$(JAVA_APPS)) helm-lint ## Everything CI runs

# ── Web (Next.js, pnpm) ──────────────────────────────────────────────────────

.PHONY: web-setup web-lint web-test web-build web-ci web-dev
web-setup: ## Install web dependencies from the lockfile
	cd $(WEB) && $(PNPM) install --frozen-lockfile

web-lint: ## Typecheck, lint and format-check the web app
	cd $(WEB) && $(PNPM) exec next typegen
	cd $(WEB) && $(PNPM) exec tsc --noEmit -p tsconfig.json
	cd $(WEB) && $(PNPM) lint --quiet
	cd $(WEB) && $(PNPM) format:check

web-test: ## Web unit and component tests (Jest)
	cd $(WEB) && $(PNPM) exec jest --ci --silent

web-build: ## Production build of the web app
	cd $(WEB) && NEXT_TELEMETRY_DISABLED=1 NEXT_PUBLIC_APP_MODE=enterprise $(PNPM) build

web-ci: web-setup web-lint web-test web-build ## Full web check

web-dev: ## Run the web app in dev mode on http://localhost:3000
	cd $(WEB) && $(PNPM) dev

# ── Java apps (Maven) ────────────────────────────────────────────────────────
# `verify` runs unit tests (Surefire) and, where an app defines them,
# integration tests (Failsafe). Testcontainers suites need a Docker daemon.

# Pattern rules, deliberately not .PHONY: make skips implicit-rule search for
# phony targets, so `make server-test` would find no recipe.

%-setup:
	cd apps/$* && $(MVN) dependency:go-offline -q

%-test:
	cd apps/$* && $(MVN) verify

%-build:
	cd apps/$* && $(MVN) -DskipTests package

%-ci:
	cd apps/$* && $(MVN) verify

# ── Deploy ───────────────────────────────────────────────────────────────────

.PHONY: helm-lint
helm-lint: ## Lint the Helm charts
	@command -v helm >/dev/null || { echo "helm not installed, skipping"; exit 0; }
	helm lint deploy/charts/certping --set url=https://certping.example.com
	helm lint deploy/charts/certping-agent --set serverUrl=https://certping.example.com
	helm template certping deploy/charts/certping --set url=https://certping.example.com >/dev/null
	helm template certping-agent deploy/charts/certping-agent --set serverUrl=https://certping.example.com >/dev/null

# ── Git hooks ────────────────────────────────────────────────────────────────

.PHONY: hooks
hooks: ## Use the repository's Git hooks (.githooks at the repo root)
	git config core.hooksPath .githooks

# ── Licenses ─────────────────────────────────────────────────────────────────

.PHONY: notices notices-check
notices: ## Regenerate the third-party notices the images ship (commit the result)
	.github/scripts/third-party-notices.sh

notices-check: ## Fail if the committed third-party notices are stale
	.github/scripts/third-party-notices.sh --check

.PHONY: license-headers license-headers-check
license-headers: ## Add the copyright and license header to source files that lack it
	python3 .github/scripts/license-headers.py --fix

license-headers-check: ## Fail if a source file has no copyright and license header
	python3 .github/scripts/license-headers.py

# ── Security scans (same tools and versions as CI) ───────────────────────────

.PHONY: scan-secrets scan-deps
scan-secrets: ## Scan the current branch's history for secrets (gitleaks)
	gitleaks git --redact --no-banner --log-opts="HEAD" .

scan-deps: ## Scan dependencies, Dockerfiles and charts (trivy)
	trivy fs --config .github/trivy.yaml --offline-scan .

# ── Local images and stack ───────────────────────────────────────────────────
# Local builds are tagged dev; the Compose kit and the all-in-one default to the
# released version otherwise.

CERTPING_DEV_VERSION ?= dev
COMPOSE := CERTPING_VERSION=$(CERTPING_DEV_VERSION) docker compose -f deploy/compose/docker-compose.yml

.PHONY: images up down
images: ## Build every image from source, tagged dev, and the all-in-one as certping-allinone:dev
	# Building reads no secrets; the placeholder only satisfies the Compose file's required check
	# on a fresh clone with no deploy/compose/.env.
	REDIS_PASSWORD=$${REDIS_PASSWORD:-build-only} $(COMPOSE) build
	docker build -f deploy/all-in-one/Dockerfile --build-arg CERTPING_VERSION=$(CERTPING_DEV_VERSION) \
		-t certping-allinone:$(CERTPING_DEV_VERSION) .

up: ## Build and start the Compose kit from source (runs deploy/compose/setup.sh once)
	@test -f deploy/compose/.env || (cd deploy/compose && ./setup.sh)
	$(COMPOSE) up -d --build

down: ## Stop the Compose kit (data volumes are kept)
	$(COMPOSE) down
