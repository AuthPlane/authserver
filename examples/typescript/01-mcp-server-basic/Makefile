.PHONY: run verify clean distclean status logs check-prereqs docker-run docker-clean

# `make run` is the basic, fast path: the AS runs as a published image
# (no build) and the demo MCP server runs natively via tsx. The shell
# glue lives in `../../_shared/native-*.sh`.
#
# `make docker-run` is the all-in-containers variant (slower first build,
# uses the per-server Dockerfile + docker-compose.yml).

SHARED       := ../../_shared
AS_CONTAINER ?= authplane-tier01-as
AS_IMAGE     ?= authplane/authserver:latest
MCP_PORT     ?= 8080

run: check-prereqs node_modules
	@[ -f .env ] || cp .env.example .env
	@set -a; . ./.env; set +a; \
	  AS_CONTAINER=$(AS_CONTAINER) AS_IMAGE=$(AS_IMAGE) $(SHARED)/native-as.sh start
	@set -a; . ./.env; set +a; \
	  PORT=$(MCP_PORT) AUTHPLANE_RESOURCE=http://localhost:$(MCP_PORT)/mcp \
	  $(SHARED)/native-proc.sh start mcp ./node_modules/.bin/tsx server.ts
	@echo "  → make verify   (or 'make logs' / 'make status' if something looks off)"

node_modules: package.json
	npm install --silent --no-audit --no-fund
	@touch $@

check-prereqs:
	@$(SHARED)/check-prereqs.sh
	@command -v node >/dev/null || (echo "ERROR: node not found. Install Node.js 22+ (https://nodejs.org)." >&2; exit 1)
	@nodever=$$(node -p 'parseInt(process.versions.node.split(".")[0],10)'); \
	 if [ "$$nodever" -lt 22 ]; then \
	   echo "ERROR: node $$(node -v) is too old. Install Node.js 22+." >&2; exit 1; \
	 fi
	@command -v npm >/dev/null || (echo "ERROR: npm not found (should ship with Node)." >&2; exit 1)

verify:
	@./scripts/verify.sh

status:
	@if docker ps --filter name=$(AS_CONTAINER) --format '{{.Status}}' | grep -q .; then \
	   docker ps --filter name=$(AS_CONTAINER) --format 'authserver:  {{.Status}}'; \
	 else echo "authserver:  not running"; fi
	@$(SHARED)/native-proc.sh status mcp

logs:
	@echo "=== authserver ==="; AS_CONTAINER=$(AS_CONTAINER) $(SHARED)/native-as.sh logs
	@echo "=== mcp ==="; $(SHARED)/native-proc.sh logs mcp

clean:
	@$(SHARED)/native-proc.sh stop mcp
	@AS_CONTAINER=$(AS_CONTAINER) $(SHARED)/native-as.sh stop
	@rm -rf .run
	@echo "stopped processes + AS container. '.env' and node_modules kept; run 'make distclean' to also remove them."

distclean: clean
	@rm -f .env

# --- optional: docker-compose variant (everything in containers) ------------
docker-run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	docker compose up -d --build

docker-clean:
	docker compose down -v --remove-orphans
	@rm -f .env
