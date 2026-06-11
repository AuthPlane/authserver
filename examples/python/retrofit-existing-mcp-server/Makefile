.PHONY: run verify diff clean distclean status logs check-prereqs docker-run docker-clean

# `make run` is the basic, fast path: the AS runs as a published image
# (no build) and the two demo MCP servers run natively as Python
# processes in a shared virtualenv. The shell glue that starts/stops
# the AS container and the two processes lives in
# `../../_shared/native-{as,proc}.sh`.
#
# `make docker-run` is the all-in-containers variant (slower first
# build, uses the per-server Dockerfiles + docker-compose.yml).

SHARED       := ../../_shared
AS_CONTAINER ?= authplane-retrofit-as
AS_IMAGE     ?= authplane/authserver:latest
BEFORE_PORT  ?= 8080
AFTER_PORT   ?= 8090
# FastMCP requires Python 3.12+. Auto-pick the first 3.13 / 3.12 / 3 on
# PATH; override with `PY=python3.12 make run` if your system default
# is older than 3.12.
PY           ?= $(shell command -v python3.13 || command -v python3.12 || command -v python3)

run: check-prereqs .run/.venv-ready
	@[ -f .env ] || cp .env.example .env
	@set -a; . ./.env; set +a; \
	  AS_CONTAINER=$(AS_CONTAINER) AS_IMAGE=$(AS_IMAGE) $(SHARED)/native-as.sh start
	@PORT=$(BEFORE_PORT) \
	  $(SHARED)/native-proc.sh start before .run/.venv/bin/python before/server.py
	@set -a; . ./.env; set +a; \
	  PORT=$(AFTER_PORT) AUTHPLANE_BASE_URL=http://localhost:$(AFTER_PORT) \
	  $(SHARED)/native-proc.sh start after .run/.venv/bin/python after/server.py
	@echo "  → make verify   (or 'make logs' / 'make status' if something looks off)"

# One shared venv with both before/ and after/ installed (after/'s deps
# are a superset of before/'s). Re-running `make run` reuses it.
.run/.venv-ready: before/pyproject.toml after/pyproject.toml
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
	.run/.venv/bin/pip install --quiet -e ./before -e ./after
	@touch $@

check-prereqs:
	@$(SHARED)/check-prereqs.sh
	@if [ -z "$(PY)" ]; then \
	   echo "ERROR: no python3 found on PATH. Install Python 3.12+." >&2; exit 1; \
	 fi

verify:
	@./scripts/verify.sh

# `make diff` shows the exact code change between the unauthed and authed
# servers. This is the answer to "what did adding Authplane cost me?".
diff:
	@diff -u before/server.py after/server.py || true

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
	@rm -f .run/before.log .run/after.log
	@echo "stopped processes + AS container. '.env' and the venv (.run/.venv) kept; run 'make distclean' for full reset."

# Full reset: clean + remove .env (whose AS keys you may have edited) + the
# venv (so the next run reinstalls from scratch). Use before sharing the
# directory or switching examples.
distclean: clean
	@rm -rf .run .env

# --- optional: docker-compose variant (everything in containers) ------------
# Run this if you want to see what the same example looks like packaged for
# deployment — slim Python base + compose-managed networking. Slower
# first build (~1 min); subsequent runs cached.

docker-run: check-prereqs
	@[ -f .env ] || cp .env.example .env
	docker compose up -d --build

docker-clean:
	docker compose down -v --remove-orphans
	@rm -f .env
