# Dockerfile for wallet-conformance-test CLI
FROM node:22-alpine@sha256:e4bf2a82ad0a4037d28035ae71529873c069b13eb0455466ae0bc13363826e34

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
