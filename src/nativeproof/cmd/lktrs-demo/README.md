# Watershed sensor cooperative demo

A local application of the native Lk-TRS research profile: three participants
share sensor reports, each with three counter slots per issue across all their
devices. Sensor readings and enrollment identities are simulated. Proofs,
authorized verification, linking, tracing and independent CLI verification are
computed by the actual backend. There is no mock or recorded-success mode.

## Run

From the repository root:

```sh
bash scripts/run-demo.sh
```

Open **http://127.0.0.1:8787**. Choose **连续运行全部步骤** to run the complete
scenario, or advance one step at a time. The pause button lets the current step
finish. Closing or refreshing the page does not cancel an active proof; refresh
recovers the server's current state. Ctrl+C in the terminal stops the server.

This path needs Go 1.25.7+ (or Go's enabled toolchain auto-download), Python 3.8+
for the exported verifier script, and a browser. It uses the existing Go module;
PBC, CMake and a Node build are not required for this demo. Go may download the
pinned module dependencies on first build. The UI then works without external
web assets or network calls.

First setup takes several minutes and several GB of RAM. Setup is generated
once under `local/demo/setup`, with its recorded manifest pin in
`local/demo/setup-pin.txt`. Subsequent runs validate and reuse it. Proofs remain
real and may take tens of seconds each; the page reports actual elapsed time,
not a simulated percentage. `--port 0` selects a free port. To use another port:

```sh
bash scripts/run-demo.sh --port 8790
```

Each scenario gets a fresh issue, local authority, participant keys and private
`local/demo/run-*` directory. Reset asks for confirmation before discarding the
current participant session. It preserves the previous evidence and setup,
then creates fresh participants. Wallets are reopened between submissions to
exercise durable counters; process restart does **not** recover a participant
session. Random wrapping keys live only in process memory. The demo intentionally
keeps Alice's scalar in memory to perform the clearly labeled malicious branch.
Do not use real identities, secrets or sensor data here.

Only one server may use a data directory. A custom `--data` directory must be
owner-only (0700); keep it under `local/`. If setup was interrupted during export,
the application fails closed rather than silently replacing it. Preserve the
partial directory for inspection and start with a fresh directory, for example
`--data local/demo-retry`. A completed setup can be reused explicitly:

```sh
bash scripts/run-demo.sh --data local/demo-reuse \
  --setup /absolute/path/to/locally-trusted-setup \
  --manifest-sha256 TRUSTED_PIN
```

The setup needs capacity at least four. Obtain the pin from a trusted source;
hashing an arbitrary downloaded manifest does not authenticate it.

## The eight steps

1. **Enroll.** Alice has two accounts; Bob and Carol have one each. A local
   Ed25519 authority endorses setup and the ordered ring after possession checks.
2. **Submit.** Alice's first device produces a real signature for a synthetic
   temperature report. Verification loads only the exported public setup.
3. **Switch devices.** Reopen Alice's encrypted wallet and submit from her second
   account. Her next counter is shared; the two signatures link, with different
   serials. Pairwise tracing classifies this pair as legal.
4. **Compare users.** Bob submits. His pseudonym differs in this sample. This
   observation does not establish a general anonymity or collision theorem.
5. **Exhaust quota.** Alice signs a third report; the fourth honest request is
   refused by the wallet without issuing a proof or consuming another slot.
6. **Reuse maliciously.** Bypass the wallet and deliberately reuse Alice's counter
   zero for a different message. The proof verifies, but the application traces
   the pair to the enrolled `alice` label and rejects that report. Reuse can be
   traced before the fourth signature; the trigger is equal S and unequal R.
7. **Revoke.** Remove both Alice accounts and publish epoch 2. Old-ring proofs
   cannot serve as current submissions. Alice's historical proof still verifies
   under its historical policy. Bob signs a fresh proof in the new ring.
8. **Reproduce.** Six separate CLI invocations verify all report signatures;
   additional invocations check the expected message-mismatch and policy-mismatch
   diagnostics for a changed message and an old registry presented
   under current policy. The UI enables a public evidence ZIP after these pass.

The public stream omits the signing account. The operator panel knows the
scripted identities; the whole scenario is orchestrated by one local process,
not distributed clients. A traced user label comes from the authority-signed
registry. It does not establish civil identity, extract the private scalar, or
identify which account signed.

## Inspect and independently verify

Select a report to inspect its exact message, nym, serial S, member epoch, measured
proof/verification time, and complete signature-envelope size. The last report
is selected automatically when a step finishes. Expected rejections appear as
checks; unexpected errors stop the run and require a reset (proof failures can
burn a reserved counter).

Download **导出公开证据**, unzip into a local directory, and run:

```sh
python3 verify.py --verifier /absolute/path/to/local/demo/bin/lktrs-native
```

The export contains 40 public files: public setup without PK, approval, six sets
of message/signature/context/policy/registry, current policy/registry, a tampered
message, results, instructions and a Python verifier script. The same files are
saved in `local/demo/run-*/export/`. No wallet, wrapping key, private scalar,
authority private key or private witness is included. The verification CLI
does not load the original server state. Report 05 intentionally verifies as a
signature even though the application rejects its duplicate-counter use.

The exported authority and policies are local demo fixtures, not independent
trust anchors. Their validity is **24 hours after initialization**; the CLI uses
the real clock. The export's instructions also explain historical stateless
verification after expiry, which does not establish current authorization.

## Architecture and boundary

`main.go` binds only IPv4 loopback. `server.go` embeds the offline UI, serializes
workflow actions and rejects foreign hosts/origins, cross-site requests, missing
mutation tokens, ambiguous JSON and out-of-order steps. It is a trusted local
operator surface, not a remotely authenticated signing service. Local users with
access to the server can act as the operator. Do not proxy it to the internet.

`engine.go` composes existing `SignerVault`, `AuthorizedVerifier`, public `Link`,
`Trace`, enrollment and registry APIs. It does not modify the circuit or legacy
code. `export.go` uses an explicit public-file allowlist and invokes the native
CLI without a shell. One serialized job runs at a time; state polling stays
responsive during setup and proving. Runtime files live under ignored `local/`.

The [protocol](../../SPEC.md) and [security contract](../../SECURITY.md) apply:
single-party setup, issue-scoped cross-ring linkage, the documented anonymity
counterexample, enrollment assumptions and rollbackable local wallets remain
research limitations. This demo is not a blockchain, live IoT deployment,
production acceptance test, full security proof or MPC ceremony.

## Tests

```sh
go -C src/nativeproof test ./cmd/lktrs-demo
go -C src/nativeproof test -race ./cmd/lktrs-demo
node --test tests/demo_ui.test.cjs
python3 tests/demo_export_test.py
```

The client regression tests use Node 22's built-in test runner (no packages).
Node is needed only for these development tests, not to build or run the demo.
They cover failed requests, out-of-order polling responses, connection recovery
and reset cancellation. Export regressions reject unrelated CLI errors such as
missing files instead of reporting them as successful cryptographic checks.

The real workflow regression performs actual setup and six proofs. Build the
separate verifier using the launcher first, or `go build ./cmd/lktrs-native`, then:

```sh
LKTRS_PROVE=1 LKTRS_DEMO_CLI="$PWD/local/demo/bin/lktrs-native" \
  go -C src/nativeproof test -count=1 -timeout=30m \
  -run '^TestDemoRealProofWorkflow$' -v ./cmd/lktrs-demo
```

Optional `LKTRS_DEMO_SETUP` and `LKTRS_DEMO_PIN` reuse a trusted local setup
together. Without both, the test creates fresh setup. The regression checks
shared counters, linking, quota refusal, replay versus tracing, user-wide
revocation, post-revocation signing, independent CLI results and export contents.

The regular native CMake configuration also builds `lktrs-demo` and registers
this regression as the slow `native_application_demo` CTest. To launch that binary
from the repository root, use `build/native/lktrs-demo --verifier
build/native/lktrs-native`. CI's existing Go test job covers the fast demo tests;
its manual slow-test dispatch includes the real application workflow.
