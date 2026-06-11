.PHONY: run verify clean

# `make run` prints the order of operations; tier-02's agent doesn't bring
# up its own stack — it talks to the tier-01 MCP server.
run:
	@cp -n .env.example .env || true
	@echo "Tier 02 agent runs against the tier-01 MCP server."
	@echo "1) cd ../01-mcp-server-basic && make run && make verify   # brings up authserver + MCP, registers resource/client"
	@echo "2) export the CLIENT_ID/CLIENT_SECRET printed by step 1 into this directory's .env"
	@echo "3) make verify   # runs the agent and asserts it echoes through the protected MCP endpoint"

verify:
	@./scripts/verify.sh

clean:
	@rm -f .env
