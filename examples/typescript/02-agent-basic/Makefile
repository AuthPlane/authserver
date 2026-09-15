.PHONY: run verify clean distclean

# Tier 02 has no stack of its own: the agent talks to the tier-01 MCP server
# and the authserver that tier 01 brought up. `make run` only installs the
# agent's dependencies and prints the order of operations; `make verify`
# registers a resource + client against the running AS and runs `agent.ts`
# natively via tsx.

run: node_modules
	@cp -n .env.example .env || true
	@echo "Tier 02 agent runs against the tier-01 MCP server."
	@echo "1) cd ../01-mcp-server-basic && make run   # brings up authserver + the protected MCP server"
	@echo "2) make verify                              # registers resource/client, runs agent.ts, asserts the authenticated call"

node_modules: package.json package-lock.json
	npm ci --no-audit --no-fund
	@touch $@

verify: node_modules
	@./scripts/verify.sh

clean:
	@rm -f .env

distclean: clean
	@rm -rf node_modules
