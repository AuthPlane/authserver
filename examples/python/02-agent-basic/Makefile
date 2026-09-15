.PHONY: run verify clean distclean

# Tier 02 has no stack of its own: the agent talks to the tier-01 MCP server
# and the authserver that tier 01 brought up. `make run` only prepares the
# virtualenv and prints the order of operations; `make verify` registers a
# resource + client against the running AS and runs `agent.py` natively.

# FastMCP and the SDK examples target Python 3.12+. Auto-pick the first
# 3.13 / 3.12 / 3 on PATH; override with `PY=python3.12 make run`.
PY ?= $(shell command -v python3.13 || command -v python3.12 || command -v python3)

run: .run/.venv-ready
	@cp -n .env.example .env || true
	@echo "Tier 02 agent runs against the tier-01 MCP server."
	@echo "1) cd ../01-mcp-server-basic && make run   # brings up authserver + the protected MCP server"
	@echo "2) make verify                              # registers resource/client, runs agent.py, asserts the authenticated call"

.run/.venv-ready: pyproject.toml
	@mkdir -p .run
	@if [ -z "$(PY)" ]; then echo "ERROR: no python3 found on PATH" >&2; exit 1; fi
	$(PY) -m venv .run/.venv
	.run/.venv/bin/pip install --quiet --upgrade pip
	.run/.venv/bin/pip install --quiet -e .
	@touch $@

verify: .run/.venv-ready
	@./scripts/verify.sh

clean:
	@rm -f .env

distclean: clean
	@rm -rf .run build *.egg-info
