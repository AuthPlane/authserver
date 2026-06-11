FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json ./
COPY server.ts agent.ts ./

EXPOSE 8080

# Default to running the FastMCP server. The agent service in
# docker-compose.yml overrides this with `command: ["npx", "tsx", "agent.ts"]`.
CMD ["npx", "tsx", "server.ts"]
