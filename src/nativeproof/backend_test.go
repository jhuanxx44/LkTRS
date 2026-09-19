package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGroth16Connected(t *testing.T) {
	if os.Getenv("LKTRS_PROVE") != "1" {
		t.Skip("set LKTRS_PROVE=1 for real connected Groth16 setup/prove")
	}
	p, accounts, st, w := fixture(t)
	ctx, err := NewVerificationContext(p, accounts, st.Issue, st.K)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	prover, verifier, err := NewBackend()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("connected setup=%v", time.Since(start))
	start = time.Now()
	signed, err := prover.Prove(p, st, w)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("connected prove=%v proof_bytes=%d", time.Since(start), len(signed.Proof.Data))
	key, err := verifier.KeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	ch, kid := verifier.IDs()
	expectedHash, err := ExpectedCircuitHash()
	if err != nil {
		t.Fatal(err)
	}
	if ch != expectedHash {
		t.Fatal("backend circuit identity is not the compiled R1CS digest")
	}
	wrongHash := ch
	wrongHash[0] ^= 1
	if _, err := LoadVerifier(key, wrongHash, kid); err == nil {
		t.Fatal("unregistered circuit hash accepted")
	}
	independent, err := LoadVerifier(key, ch, kid)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if err = independent.Verify(ctx, []byte("message one"), signed); err != nil {
		t.Fatal(err)
	}
	t.Logf("independent public-only verify=%v", time.Since(start))
	bad := signed
	bad.Statement.MessageDigest = sha256.Sum256([]byte("different"))
	if independent.Verify(ctx, []byte("different"), bad) == nil {
		t.Fatal("altered message accepted")
	}
	if independent.Verify(ctx, []byte("different"), signed) == nil {
		t.Fatal("wrong requested message accepted")
	}
	bad = signed
	bad.Proof.Data = append(append([]byte{}, signed.Proof.Data...), 0)
	if independent.Verify(ctx, []byte("message one"), bad) == nil {
		t.Fatal("trailing proof bytes accepted")
	}
	removed := append([]Account{}, accounts[:1]...)
	removed = append(removed, accounts[2:]...)
	removedCtx, err := NewVerificationContext(p, removed, st.Issue, st.K)
	if err != nil {
		t.Fatal(err)
	}
	if independent.Verify(removedCtx, []byte("message one"), signed) == nil {
		t.Fatal("old ring signature accepted after exit")
	}
	// Host-consistent mutation: alter message AND recompute R to pass host
	// checks, but retain the proof. Rejection must now come from Groth16.
	bad = signed
	bad.Statement.MessageDigest = sha256.Sum256([]byte("different"))
	bad.Statement.R, err = Challenge(bad.Statement)
	if err != nil {
		t.Fatal(err)
	}
	if independent.Verify(ctx, []byte("different"), bad) == nil {
		t.Fatal("Groth16 statement binding absent")
	}
	// A commitment count cannot be used to allocate an arbitrary slice.
	bad = signed
	bad.Proof.Data = append([]byte{}, signed.Proof.Data...)
	binary.BigEndian.PutUint32(bad.Proof.Data[128:132], 257)
	decodeErr := independent.Verify(ctx, []byte("message one"), bad)
	if decodeErr == nil || !strings.Contains(decodeErr.Error(), "commitment count") {
		t.Fatalf("decoder count was not rejected before decoding: %v", decodeErr)
	}
	// Encode/decode an actual proof and verify from only public material.
	raw, err := MarshalSigned(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalSigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = independent.Verify(ctx, []byte("message one"), decoded); err != nil {
		t.Fatal(err)
	}
	entries := []Registration{{"bob", accounts[0]}, {"alice", accounts[1]}, {"alice", accounts[2]}}
	registry, err := NewRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewSnapshot(p, accounts)
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := NewSigner(w.X)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := wallet.Sign(prover, ring, 1, st.Issue, st.K, []byte("counter zero"), 102)
	if err != nil {
		t.Fatal(err)
	}
	one, err := wallet.Sign(prover, ring, 2, st.Issue, st.K, []byte("counter one on another account"), 103)
	if err != nil {
		t.Fatal(err)
	}
	linked, err := independent.Link(ctx, []byte("counter zero"), zero, ctx, []byte("counter one on another account"), one)
	if err != nil || !linked {
		t.Fatalf("same-user link: %v", err)
	}
	result, err := independent.Trace(ctx, []byte("counter zero"), zero, ctx, []byte("counter one on another account"), one, registry)
	if err != nil || result.Status != TraceLegal {
		t.Fatalf("legal counters: %+v %v", result, err)
	}
	result, err = independent.Trace(ctx, []byte("message one"), signed, ctx, []byte("counter one on another account"), one, registry)
	if err != nil || result.Status != TraceTraced || result.UserID != "alice" {
		t.Fatalf("cross-account repeated counter: %+v %v", result, err)
	}
	want, err := TraceKey(w.X)
	if err != nil || !result.Key.Equal(&want) {
		t.Fatal("trace did not recover x*u")
	}
	result, err = independent.Trace(ctx, []byte("message one"), signed, ctx, []byte("message one"), decoded, registry)
	if err != nil || result.Status != TraceReplay {
		t.Fatalf("replay: %+v %v", result, err)
	}
	two, err := wallet.Sign(prover, ring, 2, st.Issue, st.K, []byte("counter two"), 104)
	if err != nil {
		t.Fatal(err)
	}
	if err = independent.Verify(ctx, []byte("counter two"), two); err != nil {
		t.Fatal(err)
	}
	if wallet.NextCounter(st.Issue) != 3 {
		t.Fatal("accounts did not share counter")
	}
	if _, err = wallet.Sign(prover, ring, 1, st.Issue, st.K, []byte("exhausted"), 105); err == nil {
		t.Fatal("honest wallet exceeded k")
	}
	revoked, err := registry.RevokeUser(ring, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked.Accounts()) != 1 {
		t.Fatal("user revocation left another account")
	}
	revokedCtx, err := NewVerificationContext(p, revoked.Accounts(), st.Issue, st.K)
	if err != nil {
		t.Fatal(err)
	}
	if independent.Verify(revokedCtx, []byte("counter two"), two) == nil {
		t.Fatal("current-ring revocation policy not enforced")
	}
	t.Log("real proofs: cross-account link, legal counters, duplicate-counter trace, replay, quota, user revocation and wire roundtrip PASS")

}
