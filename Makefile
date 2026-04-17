BINARY_NAME := btc-heist
EXTRA_BUILD_FLAGS=-buildvcs=false
LDFLAGS=-s -w
PKG := main
.DEFAULT_GOAL := build

# Dynamically set version and commit using git
VERSION := $(shell (git describe --tags --abbrev=0 2>/dev/null || echo ""))
COMMIT := $(shell (git rev-parse --short HEAD 2>/dev/null || echo ""))

# Append -X flags to LDFLAGS
LDFLAGS += -X '$(PKG).version=$(VERSION)' -X '$(PKG).commit=$(COMMIT)'

.PHONY: build test clean mod fetch

build: ## Builds btc-heist for your current platform
	go build $(EXTRA_BUILD_FLAGS) -o bin/${BINARY_NAME} main.go

build-prod: ## Builds btc-heist for your current platform with production flags
	go build $(EXTRA_BUILD_FLAGS) -ldflags="${LDFLAGS}" -o bin/${BINARY_NAME} main.go

build-darwin: ## Builds btc-heist for darwin
	@printf "%s\n" "==== Building for Darwin ====="
	env GOOS=darwin GOARCH=arm64 go build $(EXTRA_BUILD_FLAGS) -o bin/${BINARY_NAME}_darwin_arm64 main.go
	env GOOS=darwin GOARCH=amd64 go build $(EXTRA_BUILD_FLAGS) -o bin/${BINARY_NAME}_darwin_amd64 main.go
	lipo -create -output bin/${BINARY_NAME}_darwin bin/${BINARY_NAME}_darwin_arm64 bin/${BINARY_NAME}_darwin_amd64

build-darwin-amd64-prod: ## Builds btc-heist for darwin amd64 with production flags
	@printf "%s\n" "==== Building for Darwin amd64 (Production) ====="
	env GOOS=darwin GOARCH=amd64 go build $(EXTRA_BUILD_FLAGS) -ldflags="${LDFLAGS}" -o bin/${BINARY_NAME}_darwin_amd64 main.go

build-darwin-arm64-prod: ## Builds btc-heist for darwin arm64 with production flags
	@printf "%s\n" "==== Building for darwin arm64 (Production) ====="
	env GOOS=darwin GOARCH=arm64 go build $(EXTRA_BUILD_FLAGS) -ldflags="${LDFLAGS}" -o bin/${BINARY_NAME}_darwin_arm64 main.go

build-linux-arm64: ## Builds btc-heist for linux arm64
	@printf "%s\n" "==== Building for linux arm64 ====="
	env GOOS=linux GOARCH=arm64 go build $(EXTRA_BUILD_FLAGS) -o bin/${BINARY_NAME}_linux_arm64 main.go

build-linux-arm64-prod: ## Builds btc-heist for linux arm64 with production flags
	@printf "%s\n" "==== Building for linux arm64 (Production) ====="
	env GOOS=linux GOARCH=arm64 go build $(EXTRA_BUILD_FLAGS) -ldflags="${LDFLAGS}" -o bin/${BINARY_NAME}_linux_arm64 main.go

build-linux-amd64: ## Builds btc-heist for linux amd64
	@printf "%s\n" "==== Building for linux amd64 ====="
	env GOOS=linux GOARCH=amd64 go build $(EXTRA_BUILD_FLAGS) -o bin/${BINARY_NAME}_linux_amd64 main.go

build-linux-amd64-prod: ## Builds btc-heist for linux amd64 with production flags
	@printf "%s\n" "==== Building for linux amd64 (Production) ====="
	env GOOS=linux GOARCH=amd64 go build $(EXTRA_BUILD_FLAGS) -ldflags="${LDFLAGS}" -o bin/${BINARY_NAME}_linux_amd64 main.go

build-windows-amd64: ## Builds btc-heist for windows amd64
	@printf "%s\n" "==== Building for windows amd64 ====="
	env GOOS=windows GOARCH=amd64 go build $(EXTRA_BUILD_FLAGS) -o bin/${BINARY_NAME}_windows_amd64 main.go

build-windows-amd64-prod: ## Builds btc-heist for windows amd64 with production flags
	@printf "%s\n" "==== Building for windows amd64 (Production) ====="
	env GOOS=windows GOARCH=amd64 go build $(EXTRA_BUILD_FLAGS) -ldflags="${LDFLAGS}" -o bin/${BINARY_NAME}_windows_amd64 main.go

build-all: build-darwin build-linux-arm64 build-linux-amd64 build-windows-amd64 ## Builds btc-heist for all platforms

build-all-prod: build-darwin-arm64-prod build-darwin-amd64-prod build-linux-arm64-prod build-linux-amd64-prod build-windows-amd64-prod ## Builds btc-heist for all platforms with production flags

test:
	go test ./...

clean:
	rm -f $(BINARY_NAME)

fetch:
	./scripts/fetch-addresses.sh

mod:
	go mod tidy
	go mod vendor
	go mod verify
