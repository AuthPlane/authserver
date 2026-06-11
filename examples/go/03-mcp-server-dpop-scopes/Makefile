.PHONY: run verify clean distclean status logs check-prereqs docker-run docker-clean

# `make run` is the basic, fast path: the AS runs as a published image
# (no build) and the demo MCP server runs natively as a plain Go binary.
# Running the MCP server on the host (not in a container) is what lets it —
# and the host-side agent that `make verify` runs — discover the AS at
# `localhost:9000`; an in-network container would need `authserver:9000`
# and the host agent could not then match the issuer. The shell glue that
# starts/stops the AS container and the MCP process lives in
# `../../_shared/native-{as,proc}.sh`.
#
# `make docker-run` is the all-in-containers variant (slower first build,
# uses the per-server Dockerfile + docker-compose.yml).

SHARED       := ../../_shared
AS_CONTAINER ?= authplane-tier03-as
AS_IMAGE     ?= authplane/authserver:latest
MCP_PORT     ?= 8080

run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	@mkdir -p .run
	@go build -o .run/mcp-server ./server
	@set -a; . ./.env; set +a; \
	  AS_CONTAINER=$(AS_CONTAINER) AS_IMAGE=$(AS_IMAGE) $(SHARED)/native-as.sh start
	@set -a; . ./.env; set +a; \
	  PORT=$(MCP_PORT) AUTHPLANE_RESOURCE=http://localhost:$(MCP_PORT)/mcp \
	  $(SHARED)/native-proc.sh start mcp ./.run/mcp-server
	@echo "  → make verify   (or 'make logs' / 'make status' if something looks off)"

check-prereqs:
	@$(SHARED)/check-prereqs.sh
	@command -v go >/dev/null || (echo "ERROR: go not found. Install Go 1.25+ (https://go.dev/dl/)." >&2; exit 1)

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
	@echo "stopped processes + AS container. '.env' kept; run 'make distclean' to also remove it."

distclean: clean
	@rm -f .env

# --- optional: docker-compose variant (everything in containers) ------------
docker-run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	docker compose up -d --build

docker-clean:
	docker compose down -v --remove-orphans
	@rm -f .env
