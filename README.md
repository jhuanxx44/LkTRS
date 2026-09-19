# Lk-TRS

Companion research implementation for **[Linkable, k-Times Traceable, and Revocable Ring Signature for Fine-Grained Accountability in Blockchain Transactions](https://doi.org/10.1109/JIOT.2024.3485674)** — IEEE Internet of Things Journal, 12(4):4349–4361, 2025, by Jinghuan Xie, Jun Zhou, Zhenfu Cao, Xiaolei Dong, and Kim-Kwang Raymond Choo.

## Implementation

- Setup, KeyGen, dynamic Join/Exit, signing and public-only verification.
- Issue-scoped linking, shared quotas across a user's accounts, duplicate-counter tracing and user revocation.
- A connected Groth16 circuit using BN254 q-SDH membership, secp256k1 account/trace tags and SHA-256.
- A Go proof backend with a C++17 API and bounded local process transport.

See the [protocol specification](src/nativeproof/SPEC.md) and [backend API](src/nativeproof/README.md) for the exact equations and interfaces.

## Build and run

Requires Go 1.25.7+, CMake 3.18+, a C++17 compiler, Python 3.8+, PBC, GMP and libsodium.

**macOS**

```sh
brew install cmake go pbc gmp libsodium
cmake -S . -B build/native -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH="$(brew --prefix)" -DLKTRS_NATIVE_PROOF=ON
```

**Ubuntu** (install Go separately)

```sh
sudo apt-get install build-essential cmake python3 libgmp-dev libsodium-dev flex bison curl
bash scripts/build-pbc.sh "$PWD/build/pbc-prefix"
cmake -S . -B build/native -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH="$PWD/build/pbc-prefix" -DLKTRS_NATIVE_PROOF=ON
```

Then build and test:

```sh
cmake --build build/native -j4
ctest --test-dir build/native --output-on-failure
```

The end-to-end test runs real Groth16 setup and proofs through C++ → Go; allow several minutes and several GB of RAM. Use `-LE slow` for the fast CTest suite. To test the Go backend, including duplicate-counter tracing with real proofs:

```sh
cd src/nativeproof
go test -count=1 ./...
LKTRS_PROVE=1 go test -count=1 -timeout=20m -run '^TestGroth16Connected$' -v
```

## Scope

This executable profile uses explicit parameter and encoding choices that differ from the paper; it does not reproduce the paper's security proof or performance results. Setup is local and single-party, signer keys and counters are in memory, and same-issue signatures are linkable across rings. The optional service ledger stores quota policies, revocation tombstones and consumed envelopes, not a recoverable wallet. It is intended for research, not production assets.

`src/nativeproof/` is the connected implementation; `src/protocol/` provides the C++ interface and clear reference. The witness-exposing clear reference and isolated `src/legacy/` prototype are not anonymous signing backends.
