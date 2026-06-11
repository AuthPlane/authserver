FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json ./
COPY agent.ts ./

# The agent is a one-shot client. docker-compose.yml runs it via
# `docker compose run --rm agent`.
CMD ["npx", "tsx", "agent.ts"]
