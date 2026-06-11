.PHONY: build test test-unit test-integration test-integration-postgres test-e2e test-race lint check-imports vulncheck ci-local run run-postgres docker-build docker-run clean ui

BINARY := authserver
PKG := github.com/authplane/authserver
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/authserver

test: test-unit test-integration

test-unit:
	go test ./internal/domain/... ./internal/crypto/... ./internal/config/... ./internal/brokerproto/... -v -count=1

test-integration:
	@packages=$$(go list ./internal/adapters/... ./internal/services/... ./api/... 2>/dev/null); \
	if [ -n "$$packages" ]; then \
		go test $$packages -v -count=1 -tags=integration; \
	else \
		echo "No integration test packages found (adapters/services not yet created)."; \
	fi

AUTHSERVER_TEST_PG_PORT ?= 5433

test-integration-postgres:
	@echo "Starting PostgreSQL on port $(AUTHSERVER_TEST_PG_PORT)..."
	@AUTHSERVER_TEST_PG_PORT=$(AUTHSERVER_TEST_PG_PORT) docker compose -f deploy/docker-compose.test-postgres.yml up -d --wait
	AUTHPLANE_STORAGE_POSTGRES_DSN="postgres://authserver:authserver@localhost:$(AUTHSERVER_TEST_PG_PORT)/authserver?sslmode=disable" \
		go test ./internal/adapters/postgres/... -v -count=1 -tags=integration_postgres -timeout=300s; \
		EXIT=$$?; \
		AUTHSERVER_TEST_PG_PORT=$(AUTHSERVER_TEST_PG_PORT) docker compose -f deploy/docker-compose.test-postgres.yml down; \
		exit $$EXIT

test-e2e:
	cd e2e && go test ./... -v -count=1 -tags=e2e -timeout=180s

test-race:
	go test -race ./...

# golangci-lint — keep version in sync with .github/workflows/ci.yml.
#
# golangci-lint refuses to analyze code whose go.mod targets a newer Go than the
# one golangci-lint itself was *built* with (e.g. a system binary built with
# go1.25 vs this repo's 1.26). To avoid that, we build our own with the repo's
# Go toolchain (GOTOOLCHAIN, derived from go.mod) into a local, version-stamped
# path under bin/ (gitignored) and run that — never whatever is on PATH.
GOLANGCI_LINT_VERSION ?= v2.11.4
GO_TOOLCHAIN := go$(shell awk '/^go [0-9]/{print $$2; exit}' go.mod)
GOLANGCI_LINT := $(CURDIR)/bin/golangci-lint-$(GOLANGCI_LINT_VERSION)

$(GOLANGCI_LINT):
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) (built with $(GO_TOOLCHAIN))..."
	@GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(CURDIR)/bin \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@mv $(CURDIR)/bin/golangci-lint $@

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

vulncheck:
	@command -v govulncheck >/dev/null 2>&1 || { echo "Installing govulncheck..."; go install golang.org/x/vuln/cmd/govulncheck@latest; }
	@OUTPUT=$$(govulncheck ./... 2>&1); EXIT=$$?; \
	echo "$$OUTPUT"; \
	if [ $$EXIT -eq 0 ]; then echo "No vulnerabilities found."; exit 0; fi; \
	THIRD_PARTY=$$(echo "$$OUTPUT" | grep -A1 "^Vulnerability" | grep "Module:" || true); \
	if [ -z "$$THIRD_PARTY" ]; then \
		echo ""; echo "⚠ Only Go stdlib vulnerabilities found — upgrade Go to fix."; exit 0; \
	fi; \
	echo ""; echo "✗ Third-party dependency vulnerabilities found — run 'go get' to upgrade."; exit 1

# Verify domain packages don't import infrastructure
check-imports:
	@echo "Checking domain import boundaries..."
	@for pkg in client user token session consent scope audit connector vault; do \
		imports=$$(go list -f '{{join .Imports "\n"}}' ./internal/domain/$$pkg/ 2>/dev/null | grep -v "^$$" | grep -v "github.com/gofrs/uuid" | grep "$(PKG)" | grep -v "domain" || true); \
		if [ -n "$$imports" ]; then \
			echo "VIOLATION: internal/domain/$$pkg imports non-domain package: $$imports"; \
			exit 1; \
		fi; \
	done
	@echo "Checking ports don't import adapters, services, config, or crypto..."
	@imports=$$(go list -f '{{join .Imports "\n"}}' ./internal/ports/... 2>/dev/null | grep "$(PKG)" | grep -E "(adapters|services|config|crypto)" || true); \
	if [ -n "$$imports" ]; then \
		echo "VIOLATION: ports import non-domain package: $$imports"; \
		exit 1; \
	fi
	@echo "Checking api/ doesn't import adapters or services directly..."
	@imports=$$(go list -f '{{join .Imports "\n"}}' ./api/... 2>/dev/null | grep "$(PKG)" | grep -E "(adapters|services)" || true); \
	if [ -n "$$imports" ]; then \
		echo "VIOLATION: api/ imports adapters/services: $$imports"; \
		exit 1; \
	fi
	@echo "All import boundaries clean."

run:
	go run ./cmd/authserver serve

run-postgres:
	docker compose -f deploy/docker-compose.yml up -d postgres
	AUTHPLANE_STORAGE_DRIVER=postgres \
	AUTHPLANE_STORAGE_POSTGRES_DSN="postgres://authserver:authserver@localhost:5432/authserver?sslmode=disable" \
	go run ./cmd/authserver serve

docker-build:
	docker build -t authserver:$(VERSION) -f build/Dockerfile .
	@echo "Image size:"
	@docker images authserver:$(VERSION) --format "{{.Size}}"

docker-run:
	docker run -d -p 9000:9000 \
		-v authserver-data:/data \
		-e AUTHPLANE_SERVER_ISSUER=http://localhost:9000 \
		--name authserver \
		authserver:$(VERSION)

ui:
	@if [ -f web/admin/package.json ]; then \
		cd web/admin && \
		if [ -f package-lock.json ]; then npm ci; else npm install; fi && \
		npm run build; \
	else \
		echo "web/admin/package.json not found; skipping UI build (placeholder used)"; \
	fi

ci-local: build lint check-imports test-unit vulncheck
	@echo "All local CI checks passed."

clean:
	rm -rf bin/
	docker rm -f authserver 2>/dev/null || true
	docker volume rm authserver-data 2>/dev/null || true

# -----------------------------------------------------------------------------
# Documentation generation and smoke checks
#
#   docs-smoke        — walk examples/<lang>/<NN-name>/ and run their
#                       `make run` -> health-wait -> `make verify` ->
#                       `make clean` cycle (see tools/docssmoke/run.sh).
#   docs-gen          — regenerate docs/reference/{cli,http-api,env-vars,
#                       configuration}.md from the source tree.
#   docs-check        — `docs-gen` + `docs-links` + `git diff --exit-code`
#                       so a stale reference page or a broken anchor /
#                       file link fails CI.
#   docs-links        — verify every Markdown `[text](path#fragment)` in
#                       README.md, AGENTS.md, CONTRIBUTING.md, llms.txt,
#                       docs/, and examples/ resolves.
#   loccount          — human-readable per-example line accounting.
#   loccount-banners  — rewrite the loccount banner inside each example's
#                       README.md to match the current source.
#   loccount-check    — exit 1 if any banner is stale.
#   loccount-budget   — exit 1 if any example exceeds its tier budget.
#
# docs-gen/docs-check/docs-links and loccount-check/loccount-budget back
# required gates in .github/workflows/docs.yml — a failure fails the PR.
# -----------------------------------------------------------------------------

.PHONY: docs-smoke docs-gen docs-check docs-links loccount loccount-banners loccount-check loccount-budget

docs-smoke:
	@./tools/docssmoke/run.sh $(DOCSSMOKE_ARGS)

docs-gen:
	@go run ./tools/docsgen all

docs-links:
	@go run ./tools/docslinks $(DOCSLINKS_ARGS)

docs-check: docs-gen docs-links
	@git diff --exit-code -- \
	    docs/reference/cli.md \
	    docs/reference/http-api.md \
	    docs/reference/env-vars.md \
	    docs/reference/configuration.md \
	    docs/api/public-api.yaml \
	    docs/api/admin-api.yaml

loccount:
	@go run ./tools/loccount

loccount-banners:
	@go run ./tools/loccount --regenerate-banner

loccount-check:
	@go run ./tools/loccount --check

loccount-budget:
	@go run ./tools/loccount --budget
