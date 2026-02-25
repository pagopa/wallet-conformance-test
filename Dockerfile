# Dockerfile for wallet-conformance-test CLI
FROM node:22.19.0-alpine@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9

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
