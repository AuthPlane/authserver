.PHONY: run verify clean

run:
	@cp -n .env.example .env || true
	docker compose up -d --build authserver mcp-server

verify:
	@./scripts/verify.sh

clean:
	docker compose down -v --remove-orphans
	@rm -f .env
