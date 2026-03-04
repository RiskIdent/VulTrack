# =============================================================================
# VulTrack Backend Dockerfile
# Multi-stage build with security best practices
# =============================================================================

# -----------------------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with security flags
# -trimpath: Remove file system paths from binary
# -ldflags: Strip debug info and disable DWARF generation
# BUILD_VERSION is injected via --build-arg (e.g. git describe --tags --always)
ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static' -X main.Version=${BUILD_VERSION}" \
    -o vultrack \
    ./cmd/vultrack

# -----------------------------------------------------------------------------
# Runtime stage - using distroless for minimal attack surface
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="VulTrack Backend"
LABEL org.opencontainers.image.description="Vulnerability management system backend"
LABEL org.opencontainers.image.source="https://github.com/vultrack/vultrack"

WORKDIR /app

# Copy timezone data and CA certificates from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /build/vultrack /app/vultrack

# Use non-root user (provided by distroless:nonroot)
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Health check endpoint
# Note: distroless doesn't have curl, so healthcheck is done via docker-compose

# Run the application
ENTRYPOINT ["/app/vultrack"]
