#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
umask 077
mkdir -p local/demo/bin
go -C src/nativeproof build -mod=readonly -o "$repo_root/local/demo/bin/lktrs-native" ./cmd/lktrs-native
go -C src/nativeproof build -mod=readonly -o "$repo_root/local/demo/bin/lktrs-demo" ./cmd/lktrs-demo
exec "$repo_root/local/demo/bin/lktrs-demo" --verifier "$repo_root/local/demo/bin/lktrs-native" "$@"
