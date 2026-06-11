.PHONY: run verify clean

# `make run` brings up authserver via docker-compose. The agent itself
# runs on the host via `go run ./`.
run:
	@cp -n .env.example .env || true
	docker compose up -d

verify:
	@./scripts/verify.sh

clean:
	docker compose down -v --remove-orphans
	@rm -f .env
