# Dockerfile for wallet-conformance-test CLI
FROM node:20-alpine

# Set working directory
WORKDIR /wallet-conformance-test

COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile --prod

COPY . .

# Make CLI executable
RUN chmod +x ./bin/wallet-conformance-test

ENTRYPOINT ["./bin/wallet-conformance-test"]
