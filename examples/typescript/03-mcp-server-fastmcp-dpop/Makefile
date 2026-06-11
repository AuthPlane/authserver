.PHONY: run verify clean

run:
	@cp -n .env.example .env || true
	docker compose up -d --build

verify:
	@./scripts/verify.sh

clean:
	docker compose --profile agent down -v --remove-orphans
	@rm -f .env
