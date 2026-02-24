# Dockerfile for wallet-conformance-test CLI
FROM node:22.14.0-alpine@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944

# Set working directory
WORKDIR /wallet-conformance-test

COPY package.json pnpm-lock.yaml ./

RUN npm install -g pnpm \
    && pnpm install --frozen-lockfile \
    && pnpm rebuild

COPY . .

# Make CLI executable
RUN chmod +x ./bin/wct

ENTRYPOINT ["./bin/wct"]
