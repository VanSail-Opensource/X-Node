VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

.PHONY: build build-amd64 build-arm64 test vet schemas verify
build: build-amd64 build-arm64
build-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/x-node-linux-amd64 ./cmd/x-node
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/xnodectl-linux-amd64 ./cmd/xnodectl
build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/x-node-linux-arm64 ./cmd/x-node
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/xnodectl-linux-arm64 ./cmd/xnodectl
test:
	# Xray's VLESS outbound uses uintptr-based TLS field offsets that checkptr rejects.
	go test -race -gcflags='github.com/xtls/xray-core/proxy/vless/outbound=-d=checkptr=0' -count=1 -coverprofile=coverage.out ./...
vet:
	go vet ./...
schemas:
	go run ./cmd/schema
	python3 scripts/check_schema.py
verify: vet test
	go mod verify
	git diff --check
