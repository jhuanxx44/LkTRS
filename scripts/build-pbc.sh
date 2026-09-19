#!/usr/bin/env bash
# Build the same pinned PBC release on macOS/Linux. GMP headers must be installed.
set -euo pipefail
prefix="${1:?usage: bash scripts/build-pbc.sh ABSOLUTE_INSTALL_PREFIX}"
case "$prefix" in /*) ;; *) echo "prefix must be absolute" >&2; exit 2;; esac
version=1.0.0
digest=18275a367283077bafe35f443200499e3b19c4a3754953da2a1b2f0d6b5922dc
root="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$root/build/vendor"
archive="$scratch/pbc-$version.tar.gz"
mkdir -p "$scratch"
if [ ! -f "$archive" ]; then
    curl --fail --location --retry 2 --max-time 120 \
        "https://crypto.stanford.edu/pbc/files/pbc-$version.tar.gz" -o "$archive.part"
    mv "$archive.part" "$archive"
fi
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive")"
else
    actual="$(shasum -a 256 "$archive")"
fi
if [ "${actual%% *}" != "$digest" ]; then
    echo "PBC archive checksum mismatch; refusing to build" >&2
    exit 1
fi
tar -xzf "$archive" -C "$scratch"
cd "$scratch/pbc-$version"
ac_cv_search_yywrap=yes ./configure --prefix="$prefix"
make -j2
make install
