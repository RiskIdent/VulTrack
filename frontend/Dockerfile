# =============================================================================
# VulTrack Frontend Dockerfile
# Multi-stage build - serves static files only
# =============================================================================

# -----------------------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /build

# Copy package files first for better layer caching
COPY package.json package-lock.json ./

# Install dependencies (ci for reproducible builds)
RUN npm ci --ignore-scripts

# Copy source code
COPY . .

# BUILD_VERSION is injected via --build-arg (e.g. git describe --tags --always)
ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

# Build the application
RUN npm run build

# -----------------------------------------------------------------------------
# Runtime stage - minimal static file server
# -----------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.27-alpine

LABEL org.opencontainers.image.title="VulTrack Frontend"
LABEL org.opencontainers.image.description="Vulnerability management system frontend - static files"
LABEL org.opencontainers.image.source="https://github.com/vultrack/vultrack"

# Copy built files
COPY --from=builder /build/dist /usr/share/nginx/html

# Copy nginx configuration (static files only, no API proxy)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# nginx-unprivileged runs as user nginx (101)
USER nginx

# Expose port
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
