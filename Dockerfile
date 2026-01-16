# Dockerfile for wallet-conformance-test CLI
FROM node:20-alpine@sha256:6178e78b972f79c335df281f4b7674a2d85071aae2af020ffa39f0a770265435

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
