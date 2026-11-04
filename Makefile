.PHONY: build test vet install clean

BIN=bin/aia-chain-check

build:
	go build -o $(BIN) ./cmd/aia-chain-check

test:
	go test -race ./...

vet:
	go vet ./...

install:
	go install ./cmd/aia-chain-check

clean:
	rm -rf bin
