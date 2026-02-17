# Multi-arch (amd64, arm64): build with
#   docker buildx build --platform linux/amd64,linux/arm64 -t vaultpack:tag --push .
# Or: make docker-buildx
# ---- Build stage ----
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/Skpow1234/Vaultpack/internal/cli.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /bin/vaultpack ./cmd/vaultpack

# ---- Runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/vaultpack /usr/local/bin/vaultpack

USER nonroot:nonroot
WORKDIR /work

ENTRYPOINT ["vaultpack"]
