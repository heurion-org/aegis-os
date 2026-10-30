FROM node:22-slim

RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/core/package.json packages/core/
COPY packages/core/dist/ packages/core/dist/
COPY packages/sdk/package.json packages/sdk/
COPY packages/sdk/dist/ packages/sdk/dist/
COPY examples/stock-analyst/package.json examples/stock-analyst/
COPY examples/stock-analyst/lib/ examples/stock-analyst/lib/
COPY examples/stock-analyst/server.js examples/stock-analyst/
COPY scripts/generate-gateway-certs.sh scripts/

RUN pnpm install --frozen-lockfile

EXPOSE 3080

CMD ["node", "examples/stock-analyst/server.js"]
