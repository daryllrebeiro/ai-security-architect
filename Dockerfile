# syntax=docker/dockerfile:1
# Multi-stage production build for AI Security Architect
# 100% Free-Tier & Zero-Cost Optimized: Minimal footprint (<150MB), non-root execution, zero baked secrets.

# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies required for native modules (e.g. better-sqlite3)
RUN apk add --no-cache python3 make g++ gcc

# Copy monorepo manifests
COPY package.json package-lock.json tsconfig.json ./
COPY packages/ packages/

# Install full dependencies and build all workspaces
RUN npm ci
RUN npm run build
RUN npm prune --omit=dev

# Stage 2: Lean Production Runtime
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

# Install runtime dependencies for better-sqlite3
RUN apk add --no-cache libstdc++

# Create non-privileged security user
RUN addgroup -g 10001 -S secarch && \
    adduser -u 10001 -S secarch -G secarch

# Copy built distribution, production node_modules, and server entrypoint
COPY --chown=secarch:secarch --from=builder /app/package.json ./package.json
COPY --chown=secarch:secarch --from=builder /app/node_modules ./node_modules
COPY --chown=secarch:secarch --from=builder /app/packages ./packages
COPY --chown=secarch:secarch server.js ./server.js
COPY --chown=secarch:secarch sec-arch.config.yaml ./sec-arch.config.yaml

# Switch to non-root user
USER secarch

EXPOSE 8080

# Healthcheck for container runtimes
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

CMD ["node", "server.js"]
