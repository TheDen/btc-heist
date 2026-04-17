BINARY := bin/btc-heist

.DEFAULT_GOAL := build

.PHONY: build test clean mod fetch

build:
	go build -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)

fetch:
	./scripts/fetch-addresses.sh

mod:
	go mod tidy
	go mod vendor
	go mod verify
