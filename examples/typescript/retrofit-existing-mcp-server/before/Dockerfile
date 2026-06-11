FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY tsconfig.json ./
COPY server.ts ./

EXPOSE 8080

CMD ["npx", "tsx", "server.ts"]
