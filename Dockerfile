# Dockerfile for wallet-conformance-test CLI
FROM node:22.19.0-alpine@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9

# Set working directory
WORKDIR /wallet-conformance-test

COPY package.json pnpm-lock.yaml ./

RUN npm install -g pnpm@10.23.0 \
    && apk add --no-cache su-exec \
    && pnpm install --frozen-lockfile \
    && pnpm rebuild

COPY . .

# Make CLI executable
RUN chmod +x ./bin/wct \
    && chmod +x ./docker-entrypoint.sh \
    && mkdir -p ./data \
    && chown -R node:node /wallet-conformance-test

# The entrypoint prepares bind mounts as root, then drops to the non-root node
# user before starting the application.
ENTRYPOINT ["./docker-entrypoint.sh"]
