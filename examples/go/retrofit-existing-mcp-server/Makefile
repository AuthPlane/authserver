.PHONY: run verify diff clean distclean status logs check-prereqs docker-run docker-clean

# `make run` is the basic, fast path: the AS runs as a published image
# (no build) and the two demo MCP servers run natively as plain Go
# binaries. The shell glue that starts/stops the AS container and the
# two processes lives in `../../_shared/native-{as,proc}.sh`.
#
# `make docker-run` is the all-in-containers variant (slower first build,
# uses the per-server Dockerfiles + docker-compose.yml).

SHARED       := ../../_shared
AS_CONTAINER ?= authplane-retrofit-as
AS_IMAGE     ?= authplane/authserver:latest
BEFORE_PORT  ?= 8080
AFTER_PORT   ?= 8090

run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	@mkdir -p .run
	@cd before && go build -o ../.run/before-server ./...
	@cd after  && go build -o ../.run/after-server  ./...
	@set -a; . ./.env; set +a; \
	  AS_CONTAINER=$(AS_CONTAINER) AS_IMAGE=$(AS_IMAGE) $(SHARED)/native-as.sh start
	@PORT=$(BEFORE_PORT) \
	  $(SHARED)/native-proc.sh start before ./.run/before-server
	@set -a; . ./.env; set +a; \
	  PORT=$(AFTER_PORT) AUTHPLANE_RESOURCE=http://localhost:$(AFTER_PORT)/mcp \
	  $(SHARED)/native-proc.sh start after ./.run/after-server
	@echo "  → make verify   (or 'make logs' / 'make status' if something looks off)"

check-prereqs:
	@$(SHARED)/check-prereqs.sh
	@command -v go >/dev/null || (echo "ERROR: go not found. Install Go 1.25+ (https://go.dev/dl/)." >&2; exit 1)

verify:
	@./scripts/verify.sh

# `make diff` shows the exact code change between the unauthed and authed
# servers. This is the answer to "what did adding Authplane cost me?".
diff:
	@diff -u before/main.go after/main.go || true

status:
	@if docker ps --filter name=$(AS_CONTAINER) --format '{{.Status}}' | grep -q .; then \
	   docker ps --filter name=$(AS_CONTAINER) --format 'authserver:  {{.Status}}'; \
	 else echo "authserver:  not running"; fi
	@$(SHARED)/native-proc.sh status before
	@$(SHARED)/native-proc.sh status after

logs:
	@echo "=== authserver ==="; AS_CONTAINER=$(AS_CONTAINER) $(SHARED)/native-as.sh logs
	@echo "=== before ==="; $(SHARED)/native-proc.sh logs before
	@echo "=== after ==="; $(SHARED)/native-proc.sh logs after

clean:
	@$(SHARED)/native-proc.sh stop before
	@$(SHARED)/native-proc.sh stop after
	@AS_CONTAINER=$(AS_CONTAINER) $(SHARED)/native-as.sh stop
	@rm -rf .run
	@echo "stopped processes + AS container. '.env' kept; run 'make distclean' to also remove it."

# `make distclean` is the full reset: clean + remove .env (whose AS keys
# you may have edited). Use this when switching examples or before sharing
# the directory.
distclean: clean
	@rm -f .env

# --- optional: docker-compose variant (everything in containers) ------------
# Run this if you want to see what the same example looks like packaged for
# deployment — multi-stage builds, distroless runtime, compose-managed
# networking. Slower first build (~1 min); subsequent runs cached.

docker-run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	docker compose up -d --build

docker-clean:
	docker compose down -v --remove-orphans
	@rm -f .env
