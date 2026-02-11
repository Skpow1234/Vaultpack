APP_NAME   := vaultpack
MODULE     := github.com/Skpow1234/Vaultpack
BUILD_DIR  := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS    := -ldflags "-s -w -X $(MODULE)/internal/cli.Version=$(VERSION)"

.PHONY: build test lint fmt vet vulncheck fuzz clean docker-build help

## build: Compile the binary into bin/
build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./cmd/vaultpack

## test: Run all tests with race detector
test:
	go test -race -count=1 ./...

## lint: Run golangci-lint (must be installed)
lint:
	golangci-lint run ./...

## vet: Run go vet
vet:
	go vet ./...

## vulncheck: Run govulncheck for known vulnerabilities
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## fuzz: Run all fuzz targets for 30s each
fuzz:
	go test -fuzz=FuzzUnmarshalManifest -fuzztime=30s ./internal/bundle/...
	go test -fuzz=FuzzCanonicalManifest -fuzztime=30s ./internal/bundle/...
	go test -fuzz=FuzzDecryptAESGCM -fuzztime=30s ./internal/crypto/...
	go test -fuzz=FuzzEncryptDecryptRoundTrip -fuzztime=30s ./internal/crypto/...
	go test -fuzz=FuzzStreamEncryptDecryptRoundTrip -fuzztime=30s ./internal/crypto/...
	go test -fuzz=FuzzDecryptStreamCorrupted -fuzztime=30s ./internal/crypto/...

## fmt: Format code with gofumpt (falls back to gofmt)
fmt:
	@which gofumpt > /dev/null 2>&1 && gofumpt -w . || gofmt -w .

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## docker-build: Build a Docker image
docker-build:
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

## help: Show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
