.PHONY: run verify clean distclean status logs check-prereqs docker-run docker-clean

# `make run` is the basic, fast path: the AS runs as a published image
# (no build) and the demo MCP server runs natively as a Python process
# in a virtualenv. The shell glue lives in `../../_shared/native-*.sh`.
#
# `make docker-run` is the all-in-containers variant (slower first build,
# uses the per-server Dockerfile + docker-compose.yml).

SHARED       := ../../_shared
AS_CONTAINER ?= authplane-tier01-as
AS_IMAGE     ?= authplane/authserver:latest
MCP_PORT     ?= 8080
# FastMCP requires Python 3.12+. Auto-pick the first 3.13 / 3.12 / 3 on
# PATH; override with `PY=python3.12 make run` if your system default
# is older.
PY           ?= $(shell command -v python3.13 || command -v python3.12 || command -v python3)

run: check-prereqs .run/.venv-ready
	@[ -f .env ] || cp .env.example .env
	@set -a; . ./.env; set +a; \
	  AS_CONTAINER=$(AS_CONTAINER) AS_IMAGE=$(AS_IMAGE) $(SHARED)/native-as.sh start
	@set -a; . ./.env; set +a; \
	  PORT=$(MCP_PORT) AUTHPLANE_BASE_URL=http://localhost:$(MCP_PORT) \
	  $(SHARED)/native-proc.sh start mcp .run/.venv/bin/python server.py
	@echo "  → make verify   (or 'make logs' / 'make status' if something looks off)"

.run/.venv-ready: pyproject.toml
	@mkdir -p .run
	@if [ -z "$(PY)" ]; then echo "ERROR: no python3 found on PATH" >&2; exit 1; fi
	@pyver=$$($(PY) -c 'import sys; print("%d.%d" % sys.version_info[:2])'); \
	 case "$$pyver" in 3.12|3.13|3.14|3.15) ;; \
	   *) echo "ERROR: $(PY) is Python $$pyver but FastMCP needs 3.12+." >&2; \
	      echo "       Install Python 3.12+ or pass PY=/path/to/python3.12 make run." >&2; \
	      exit 1 ;; \
	 esac
	$(PY) -m venv .run/.venv
	.run/.venv/bin/pip install --quiet --upgrade pip
	.run/.venv/bin/pip install --quiet -e .
	@touch $@

check-prereqs:
	@$(SHARED)/check-prereqs.sh
	@if [ -z "$(PY)" ]; then echo "ERROR: no python3 found on PATH. Install Python 3.12+." >&2; exit 1; fi

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
	@rm -f .run/mcp.log
	@echo "stopped processes + AS container. '.env' and the venv (.run/.venv) kept; run 'make distclean' for full reset."

distclean: clean
	@rm -rf .run .env

# --- optional: docker-compose variant (everything in containers) ------------
docker-run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	docker compose up -d --build

docker-clean:
	docker compose down -v --remove-orphans
	@rm -f .env
