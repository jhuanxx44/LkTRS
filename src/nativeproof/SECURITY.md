# Security model and trust contract for native profile v1

This document analyzes the implemented relation. It provides two algebraic
lemmas, a conditional reduction structure, and explicit counterexamples. It is
**not a completed security proof or an independent cryptographic audit**.
`SPEC.md` defines the bytes and equations. The circuit and its digest are
unchanged by the provisioning and wallet APIs described here.

## Adversaries and trusted inputs

Let `r` be BN254 Fr's order and `ell` secp256k1's order. Users own nonzero
`x in Z_ell`; an account has `U=[d]u`, `Y=[x]U` for nonzero `d in Z_ell`.
Registration publishes `d` and an identity label. It therefore reveals the
user's public trace key `X=[1/d]Y=[x]u` and which registered accounts share it.
It does not by itself reveal which account signed a signature.

The verifier must trust all of the following independently of the candidate
signature:

* The exact setup manifest, and the process that generated its q-SDH parameters
  and Groth16 keys. Hash equality and an authority endorsement authenticate bytes
  and decisions; neither proves honest generation or secret erasure.
* An enrollment authority that authenticates user labels, checks possession,
  enforces one trace key per user and one user per trace key, and publishes the
  expected active ordered ring, issue, quota and epoch.
* A current policy/clock. An attacker able to roll back the trusted policy can
  replay an old, correctly signed registry snapshot.
* Honest users' key custody and counter state. A malicious signer can bypass
  the wallet, choose a previously used counter and generate another valid proof.
  The cryptographic response is tracing, not prevention of all such proofs.

The local stdio `Service` remains a trusted research signer/admin: possession
of its pipe grants its operations. The new `verify-authorized` command is a
separate verifier path. It does not retrofit authentication onto that pipe.

## Established algebra and conditional reductions

### A. Membership witness to inverse-exponent solution

For distinct member handles `A={a_1,...,a_n}`, write
`F(Z)=product_i(Z+a_i)` and `V=[F(tau)]G`. Assume prime-order nondegenerate
pairing groups, trusted consistent powers through degree at least `n`, and
an extracted witness `b,W` satisfying

```
e(W,[tau+b]H) = e(V,H),  b not in A.
```

Divide `F(Z)=(Z+b)Q(Z)+c`, with `c=F(-b) != 0`. The public powers let a
reduction compute `[Q(tau)]G` (degree `n-1`). Nondegeneracy gives

```
W = [F(tau)/(tau+b)]G,
[c^-1](W-[Q(tau)]G) = [1/(tau+b)]G.
```

The host rejects a zero accumulator and zero membership denominator. If
`tau+b=0` and `V != 0`, the membership equation cannot hold. Thus this is an
explicit algebraic reduction from a false-member witness to an inverse-exponent
solution for the actual SRS. `TestMembershipReductionAndKnownTrapdoor` checks
this identity and demonstrates forging a nonmember witness with retained tau.
A green test of the identity is not evidence that the inverse problem is hard.

To lift the lemma to accepting signatures requires **all** of:

1. Adaptive knowledge extraction for this precise gnark Groth16 instance,
   including its commitment extension, in the presence of the adversary's
   available prior proofs. Treat this as an assumption here, not a theorem
   inherited from plain Groth16 or a test of the constraint solver.
2. Collision/second-preimage resistance of the *reduced member hash*. Equal
   `SHA256(bytes) mod r` does not imply equal 256-bit digests. Ordinary SHA-256
   collision resistance alone is not the exact assumption for the reduction.
3. Hardness of the inverse-exponent problem given **all** published setup
   information, and a simulation of the other public material/oracles. The
   algebra above alone does not supply this simulation.

Under those assumptions, an accepted outsider proof yields either a proof
knowledge-extraction failure, a reduced-hash collision, or the inverse solution
above. If the extracted account is an existing honest account, its canonical
ownership equations yield `x=log_U(Y)`; a fresh-proof unforgeability reduction
would additionally need to embed a DL challenge and simulate signing queries.
That full chosen-message reduction is still open. Re-randomizing a prior proof
is not classified as a fresh-message forgery, and no strong unforgeability or
simulation extractability is claimed.

### B. Same-user duplicate-counter trace

Fix one user secret, one issue and one quota. Canonical nonzero `ut` has prime
order `ell`. For allowed counters `0 <= c < k <= 2^32-1 < ell`, with nonzero
`(s+c+1)` and `(t+c+1)`,

```
S_c = [1/(s+c+1)]ut
T_c(R) = X + [R/(t+c+1)]ut.
```

`S_c=S_c'` iff `c=c'` for this fixed user/issue: injectivity of multiplication
by a nonzero generator, inversion and addition proves this. For the same
counter and `R1 != R2`, direct elimination gives

```
[R2/(R2-R1)]T1 - [R1/(R2-R1)]T2 = X.
```

Consequently more than `k` **distinct challenge uses** by the fixed user/issue
must contain a repeated counter and permit extraction, provided all proofs
have extractable witnesses bound to this user and all uses share the quota.
This is a conditional pigeonhole argument, not a complete adversarial
k-traceability theorem. Repeated presentations with the same `R,T` are replay;
randomizing the proof bytes does not create a new challenge use. Timestamp
uniqueness is not assumed. Different challenges require the encoded transcripts
to differ and no reduced challenge-hash collision.

Tracing inputs from different users additionally need a bound on nym/serial
collisions. `nym` is a map into a group of order `r`; it cannot be injective
on all `ell-1` user secrets. Public registry consistency resolves a recovered
key to a unique enrolled label, conditional on an honest enrollment authority.
It does not extract the scalar x or identify the particular account used.
Exculpability against adversarial prior signing queries and enrollment remains
a separate reduction obligation; rejection of forged fixtures is insufficient.

## Anonymity: the counterexample and the remaining game

The original game's same-issue/different-ring identified signing queries expose
an immediate distinguisher. Obtain a signature for candidate user 0 under
another ring in issue I. Compare its nym to the challenge signature's nym in I.
In the absence of a nym collision, equality identifies candidate 0, otherwise
candidate 1. Success is 1 (advantage 1/2 under the `Pr[win]-1/2` convention).
This does not attack Groth16 zero knowledge; the identifying value is public.
`TestIssueScopedCrossRingSemantics` and real-proof regressions exercise the
underlying equality, including signatures from different accounts of one user.

A candidate **fresh-issue user-anonymity** game must at minimum require:

* Two honest, uncorrupted challenge users enrolled under a trusted registry,
  both represented in the challenge ring, with authenticated equal policy.
* No identity-labeled signing query for either candidate in the challenge issue
  in any ring, before or after challenge. A previously identified same-issue
  signature trivially defeats the game even if the challenge ring is fixed.
* No exposure of either user's witness, wallet, tracing counter reuse, or
  application metadata identifying the signer. The simulator must reproduce
  the allowed registration and other-issue signing observations.

Even this restricted game is **not proved here**. Zero knowledge hides the
witness only *conditional on the public statement*: it cannot hide information
already carried by nym, S and T. A hybrid would first replace real proofs by
simulated proofs (under the exact proof system's adaptive ZK assumption), then
need indistinguishability of the full public tag distribution

```
(X, registration metadata, issue,
 [s mod r]g0 + [t mod r]g1 + [x mod r]g2,
 [1/(s+c+1)]ut, X + [R/(t+c+1)]ut,
 permitted observations in other issues).
```

Calling this distribution indistinguishability an assumption merely names the
missing step; it does not reduce it to DL/DDH/q-DDHI. The same hashed seeds
participate in both groups; independence cannot be asserted. A separate
cross-group auxiliary-information analysis of the inverse functions is needed.
Changing nym to include the ring would change intended link/quota semantics and
would not, by itself, prove the distribution claim for S and T.

All hashes in the implementation are concrete SHA-256. A proof in a programmable
random-oracle model would need to state that idealization and its query/domain
boundaries. It would not constitute a standard-model proof of this concrete
hash. The reduction `integer -> integer mod r` is biased and lossy; a uniform
256-bit input has residues with floor/ceil(2^256/r) preimages. No statistical
uniformity claim is made. `TestDualOrderReductionIsNotScalarEquality` confirms
that x and x+r can share their BN254 reduction while remaining distinct secp
secrets and hashing to different seeds in the fixture. It does not prove a
collision bound for the full nym function.

## Authenticated setup and enrollment APIs

`TrustPolicy` is independently provisioned JSON (`lktrs/trust-policy/v1`). It
pins namespace, manifest SHA-256, separate Ed25519 setup/registry authority
public keys (canonical base64), exact nonzero registry epoch, issue and quota.
A policy obtained from the signature sender is not a trust anchor.

`SignSetupApproval` endorses the manifest fingerprint, namespace and half-open
validity interval `[not_before,not_after)`. `LoadAuthorizedVerifier` checks the
signature and scope before loading the pinned public setup. `Verify` checks
approval validity again, so a long-lived verifier does not ignore expiry.

`CreateEnrollment` proves possession of x for `Y=[x]U`: choose nonzero random
rho, commit `A=[rho]U`, compute domain-separated SHA-256 challenge e over the
namespace, setup pin, authority key, user/account IDs, U/Y/d, authority-issued
challenge and A, then return `z=rho+e*x mod ell`. `VerifyEnrollment` checks
`[z]U=A+[e]Y` and an independently expected enrollment challenge. Relabeling a
public account changes e. This is a concrete Schnorr Fiat-Shamir PoP, relying
on DL and its random-oracle analysis; it does not establish a real identity.
The authority must authenticate the user, issue/consume one-time challenges,
and enforce enrollment policy outside this library. Merely copying a PoP for
the same identity/context does not establish a fresh interactive enrollment.

`SignRegistryAuthorization` signs the ordered active entries, exact setup,
namespace, issue, k, epoch and validity interval, after rechecking PoPs and
per-user/trace-key consistency. The signed registry contains labels and d;
it is public identity metadata, not an anonymous directory. `authorizedContext`
constructs the verifier's ring from this signed list; proof-supplied rings cannot
replace it. `AuthorizedVerifier.Verify` authenticates this context before
ordinary proof verification. Authorities accept `crypto.Signer`, allowing
external Ed25519 signing services; this repository supplies no HSM/KMS adapter.

Revocation requires a new active snapshot excluding **all** accounts of the
user, plus an authenticated policy update to that epoch. Snapshot omission is
not a persistent enrollment tombstone. The authority must retain revocation
history and prevent re-enrollment. Historical policies can verify historical
snapshots; no global retroactive revocation or automatic latest-epoch discovery
is claimed. Signed snapshots at the same epoch are an authority equivocation
risk; exact epoch pins prevent downgrade, not split-view behavior. Applications
needing that guarantee must also pin/log the exact snapshot digest.

## Setup ceremony implementation and unclosed obligations

`ContributeQSDH` and `FinalizeQSDHCeremony` adapt pinned gnark Phase1, verify the
entire ordered chain, and derive G, H, HTau and the requested powers. The adapter
requires canonical compressed points, a trusted capacity-derived domain,
exact wire length and predecessor challenge **before** the third-party decoder
allocates its vectors. It requires at least two contributions and a nonzero
32-byte beacon. Those checks do not authenticate contributors, prove that they
are independent, or establish beacon timing/entropy. The receipt records
versions, capacity/domain, ordered contribution hashes, beacon and parameters
hash. Reverification requires the full chain, not just that receipt.

This is a **q-SDH parameter ceremony adapter**. It does not implement a complete
Groth16 ceremony or label a mixed/local setup as multi-party. The existing
`setup` command/portable bundle stays `local-single-party`. Low-level callers
can exercise q-SDH parameters from the adapter with the existing native relation;
production bundle import/provenance must be designed with the full ceremony.

The Phase1 transcript exposes powers through degree `2N-2`, additional G2
powers and alpha/beta sequences, even when exported Params is truncated to
capacity+1. The inverse-exponent assumption must cover those public values and
all contribution proofs. Truncating the parameter file does not hide the
transcript. The elementary lemma above does not prove this stronger assumption
or its equivalence to the paper's q-SDH instance. Prefer independent ceremonies
for the accumulator and Groth16 unless correlated-setup analysis justifies reuse.

The pinned gnark v0.16.3 `mpcsetup` implementation supports the circuit's Pedersen
commitments in Phase2. To close the Groth16 setup milestone requires:

1. Freeze the exact circuit digest, gnark versions and ceremony format; derive
   its FFT domain and bounded Phase1/Phase2 decoding budgets from that circuit.
2. Run separately authenticated participants, verify every ordered contribution,
   and retain public transcripts. Document the honest-contributor and erasure
   assumptions for both phases and commitment trapdoors.
3. Fix and authenticate a public randomness beacon observed after contribution
   closure, and reproducibly apply it. A local fixed test value is not that beacon.
4. Independently recompute Phase2 from the frozen R1CS/Phase1 output; compare all
   PK/VK bytes and commitment metadata, then generate/verify the actual native
   proof in separate processes and exercise malformed/tampered transcripts.
5. Publish an authenticated manifest binding those exact outputs and evidence.
   Obtain independent review of the implementation and the full public-SRS
   assumption. Signature endorsement is not a substitute for this review.

The local two-contribution test is a rehearsal by one operator. No independently
operated ceremony, live authority deployment, honest-party claim, or forensic
secret destruction has been completed by this repository change.

## Key custody and crash behavior

`SignerVault` stores canonical x and per-issue next-counter/quota under
XChaCha20-Poly1305 with a fresh random 192-bit nonce and wallet ID as authenticated
associated data. The format is `LKTRSV02 || walletID32 || nonce24 || ciphertext`;
the authentication tag is included in ciphertext. The unpublished AES-GCM v1
format is rejected; no silent migration occurs. The 32-byte random wrapping key
is supplied externally and never written by the API. Use a fresh independent
key per wallet. External key lifecycle management must bound aggregate use,
including failed writes/retries and any accidental key sharing. For at most
2^64 encryptions per key, the random-nonce collision union bound is below 2^-65;
this is only a nonce-collision bound, not a complete AEAD security claim. Counter
state records reservations, not every encryption attempt, and cannot enforce
that aggregate key-use limit.
Keep it in an OS/key service separate from the file; do not derive it directly
from a password. The API requires owner-only file permissions, a trusted parent
directory, and a stable advisory-lock file. Cooperating local processes use
`flock`, reload encrypted state, reserve a counter, write/sync a replacement and
sync the directory **before** proving. A crash/prover error may burn a slot;
it must not release a proof and then forget to increment. This differs from the
in-memory `Signer`, which increments only after successful proving.

File rollback and wallet cloning remain possible for an attacker with the old
ciphertext and wrapping key. Filesystem encryption/MAC does not supply freshness;
use an external monotonic transaction store or key service for that threat.
Network filesystems, malicious administrators and deletion/replacement of the
lock inode are outside the local cooperating-process contract. Account d/records
are supplied separately by the authenticated registry; the vault stores one
user x and must be reused across all its accounts/issues, not cloned per account.
The prover necessarily sees x and the witness in memory. Best-effort buffer
clearing does not establish constant time, protected memory or forensic erasure.
No HSM circuit witness protocol or deployed secure custody service is claimed.

## Sources and evidence

* [Nguyen, author full version, 2005/123](https://eprint.iacr.org/2005/123):
  provenance for the hidden-offset accumulator; the polynomial identity above
  is written out for this actual asymmetric instance instead of transferring
  the paper's theorem. The earlier source audit is not a proof of this composition.
* [Groth, 2016/260](https://eprint.iacr.org/2016/260): underlying proof-system
  reference; not an audit of the pinned implementation or commitment extension.
* [Bowe, Gabizon, Miers, 2017/1050](https://eprint.iacr.org/2017/1050): the primary
  abstract confirms the random-beacon/generic-group scope. This work does not
  claim a fresh line-by-line verification of its full security proof.
* Pinned gnark sources: [Phase1](https://github.com/Consensys/gnark/blob/v0.16.3/backend/groth16/bn254/mpcsetup/phase1.go),
  [Phase2](https://github.com/Consensys/gnark/blob/v0.16.3/backend/groth16/bn254/mpcsetup/phase2.go),
  [Seal](https://github.com/Consensys/gnark/blob/v0.16.3/backend/groth16/bn254/mpcsetup/setup.go),
  [decoder](https://github.com/Consensys/gnark/blob/v0.16.3/backend/groth16/bn254/mpcsetup/marshal.go).
  These were checked in the local Go module cache at the pinned version.
* Executable evidence: `security_test.go`, `semantics_test.go`, `trust_test.go`,
  `ceremony_test.go`, `vault_test.go`, and opt-in `TestGroth16AuthorizedWallet`.
  Tests and mutation failures establish only the assertions they exercise.
