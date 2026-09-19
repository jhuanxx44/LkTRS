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
records, so restarting still requires explicit re-enrollment and setup. It is a
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
