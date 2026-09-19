# Connected native Lk-TRS research backend

The executable specification is [SPEC.md](SPEC.md).
`circuit.go` contains a connected witness statement, `profile.go` supplies native
host arithmetic, and `backend.go` performs Groth16 setup/proving/verification.
The verifier reconstructs public inputs independently.

## Build and run

```
go build -mod=readonly -o ../../build/lktrs-native ./cmd/lktrs-native
go test -count=1 ./...
LKTRS_PROVE=1 go test -count=1 -timeout=20m -run '^TestGroth16Connected$' -v
```

The normal tests use the compiled R1CS solver. The opt-in test actually performs
Groth16 setup and multiple proofs, loads a separate public verifier, exercises
Link/kTrace and user revocation, and serializes the proof. Setup uses a local
single party and the fixed profile; this is not an MPC ceremony.

## C++ local process protocol

`lktrs-native --stdio` reads **four-byte unsigned big-endian payload length**,
then that many UTF-8 JSON bytes, and returns the same framing. Maximum payload
is 16 MiB. stdout contains only frames. The C++ `NativeProcess` API invokes it
without a shell and implements bounded I/O, deadlines and process cleanup.
Every response has `ok`, `members`, and optional `error`.

Operations (unknown fields and trailing JSON are rejected):

| op | Input | Result |
|---|---|---|
| info | none | version |
| setup | capacity, positive integer | initialize public q-SDH parameters and Groth16 keys |
| keygen | user, account strings | new account, reusing one secret for an existing user |
| join / exit | account | mutate current public ring atomically |
| revoke_user | user | exit all registered accounts of this user |
| sign | account, issue, k, message_b64, timestamp | signature_b64 |
| verify | issue, k, message_b64, signature_b64 | verified |
| link / trace | verify fields plus second_message_b64, second_signature_b64 | linked / trace and user |

`issue` is 32 bytes in lowercase hex; `message_b64` is strict standard base64
of an arbitrary byte string; `timestamp` is uint64 and `k` is a positive uint32.
The service pins k when first signing under an issue. `signature_b64` wraps
`MarshalSigned`'s public-only `LKTRSN01` binary envelope. The caller does not
supply a verification key or redefine the accumulator in `verify`.

The current service owns its accounts and signer secrets in memory and accepts
local trusted callers. `revoke_user` also installs a process-lifetime tombstone
that blocks keygen/rejoin for that user. Reinitializing it creates fresh keys
and clears the tombstone in default ephemeral mode. The optional ledger below
retains tombstones, but does not restore a wallet.
Library users can construct `Verifier` from trusted key bytes and a pinned
circuit manifest, then use `VerificationContext` from public parameters/ring
alone.
`Trace` also supports two different trusted ring snapshots under the same issue.

For a persistent local ledger, set `LKTRS_STATE_PATH` before starting
`lktrs-native`. The service atomically persists issue quota policies, revoked
user tombstones and consumed verification-envelope digests (mode 0600). A
successful `verify` consumes an envelope digest once, including in ephemeral
mode; `link` and `trace` remain pairwise analysis operations and do not consume it. This state file does not
persist private signer keys, Groth16 proving keys, q-SDH setup or active account
records, so restarting still requires re-enrollment and loading or generating
setup. It is a
local research ledger, not secure key custody or production
authorization. Do not share a state file between running processes. Replay
filtering compares envelope bytes, so independently randomized proofs are not
deduplicated by this ledger. See [SPEC.md](SPEC.md) for the exact semantics.

## Verified implementation scope

A native proof connects account ownership to its SHA-derived member identifier,
q-SDH membership, canonical x to both private seed hashes, nym in BN254 G1,
S/T in secp256k1, a nonzero transcript-derived R and a 32-bit `cnt < k`.
The selected account and seeds are never public proof inputs.

The parameter profile is an explicit correction/instantiation of inconsistent
paper notation. Its separate orders, hash encoding and message prehash do not
have a security reduction established by these tests. BN254 does not justify
128/256-bit security claims. Trusted setup, registry authentication, durable
counters and key custody need independent treatment before real use.

## Save setup and reproduce in separate processes

Run these commands from the repository root after building. Each command starts
and exits a separate process; loading never regenerates setup. Outputs are local
artifacts and must stay outside Git.

```sh
mkdir -p local
./build/native/lktrs-native setup --capacity 4 --out local/repro/setup \
  > local/setup-result.json
PIN=$(python3 -c 'import json; print(json.load(open("local/setup-result.json"))["manifest_sha256"])')
./build/native/lktrs-native export-public --setup local/repro/setup \
  --manifest-sha256 "$PIN" --out local/repro/public
./build/native/lktrs-native sample --setup local/repro/setup \
  --manifest-sha256 "$PIN" --out local/repro/sample
./build/native/lktrs-native verify --setup local/repro/public \
  --manifest-sha256 "$PIN" --context local/repro/sample/context.json \
  --message local/repro/sample/message.bin --signature local/repro/sample/signature.bin
```

Output directories must be new.
The sample uses fresh research accounts and the full native proof circuit;
only the public ring, message and signature are saved. The verifier consumes no
PK, user scalar, witness, signer database or private account exponent. Its
explicit `--context` is the expected ring/issue/quota, not a context learned
from the candidate signature.

A complete setup contains `parameters.bin`, `pk.bin`, `vk.bin`, `manifest.json`.
The public export contains the same manifest, parameters and VK, without PK.
The PK is large (hundreds of MB); loading and proving still require several GB
of RAM. PK is public proof-generation material, not a user's signing secret.
The JSON manifest records the profile, library versions, both scalar orders,
compiled R1CS digest/layout, capacity, and each artifact's byte count/digest.
No q-SDH trapdoor or Groth16 toxic waste is serialized. `--manifest-sha256`
must come from a trusted setup distribution channel; computing a hash of an
arbitrary downloaded manifest does not authenticate it or attest an MPC ceremony.

To start the C++-compatible service with existing setup:

```sh
./build/native/lktrs-native --stdio --setup local/repro/setup --manifest-sha256 "$PIN"
```

`setup` requests then fail as already initialized. Wallet accounts/counters are
still fresh: this is setup recovery, not wallet backup. Independent `verify`
CLI calls are stateless; the stdio service's additional replay ledger semantics
remain as documented above.

The reusable Go entry points are `ExportSetup`, `LoadSetup`, `LoadPublicSetup`,
`ExportPublicSetup`, `MarshalVerificationContext` and `UnmarshalVerificationContext`.
The manifest and file formats are specified in [SPEC.md](SPEC.md#portable-setup).
Run the complete setup/reload/tamper/stdio test with:

```sh
python3 tests/native_setup_roundtrip.py build/native/lktrs-native
```

It is also registered as the slow `native_setup_roundtrip` CTest. Reproduction
means using the same persisted parameters and keys, not generating identical
random setup or proof bytes on each run.
