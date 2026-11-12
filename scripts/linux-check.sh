#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
workspace=$(cd "$(dirname "$0")/.." && pwd)
cache_root="$workspace/.cache/linux-go1.27.4"
mkdir -p "$cache_root"
if [[ ! -x "$cache_root/go/bin/go" ]]; then
    if [[ ! -f "$cache_root/go.tar.gz" ]]; then
        curl --fail --location --silent --show-error https://go.dev/dl/go1.27.4.linux-amd64.tar.gz -o "$cache_root/go.tar.gz"
    fi
    printf '%s  %s\n' 7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 "$cache_root/go.tar.gz" | sha256sum -c -
    tar -xzf "$cache_root/go.tar.gz" -C "$cache_root"
fi
export PATH="$cache_root/go/bin:$PATH"
export GOCACHE="$cache_root/build-cache"
export GOMODCACHE="${GOMODCACHE:-$cache_root/module-cache}"
export CGO_ENABLED=1
cd "$workspace"
go test -race -count=1 -coverprofile="$cache_root/coverage.out" ./...
go vet ./...
go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$cache_root/x-node-linux-amd64" ./cmd/x-node
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$cache_root/x-node-linux-arm64" ./cmd/x-node
