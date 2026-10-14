#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
workspace=$(cd "$(dirname "$0")/.." && pwd)
cache_root="$workspace/.cache/linux"
mkdir -p "$cache_root"
if [[ ! -x "$cache_root/go/bin/go" ]]; then
    if [[ ! -f "$cache_root/go.tar.gz" ]]; then
        curl --fail --location --silent --show-error https://go.dev/dl/go1.27.2.linux-amd64.tar.gz -o "$cache_root/go.tar.gz"
    fi
    printf '%s  %s\n' ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5 "$cache_root/go.tar.gz" | sha256sum -c -
    tar -xzf "$cache_root/go.tar.gz" -C "$cache_root"
fi
export PATH="$cache_root/go/bin:$PATH"
export GOCACHE="$cache_root/build-cache"
if [[ -d /mnt/c/Users/txyyds/go/pkg/mod/cache/download ]]; then
    export GOMODCACHE=/mnt/c/Users/txyyds/go/pkg/mod
else
    export GOMODCACHE="$cache_root/module-cache"
fi
export CGO_ENABLED=1
cd "$workspace"
go test -race -count=1 -coverprofile="$cache_root/coverage.out" ./...
go vet ./...
go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$cache_root/x-node-linux-amd64" ./cmd/x-node
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$cache_root/x-node-linux-arm64" ./cmd/x-node
