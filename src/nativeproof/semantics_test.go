package nativeproof

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"math/big"
	"testing"
)

// These assertions pin the executable semantics, not the paper's anonymity game.
func TestIssueScopedCrossRingSemantics(t *testing.T) {
	p, accounts, original, w := fixture(t)
	otherRing := []Account{accounts[1], accounts[2]}
	changed, _, err := MakeStatement(p, otherRing, 1, w.X, accounts[2].D, original.Issue, sha256.Sum256([]byte("another ring")), 101, original.K, w.Counter)
	if err != nil {
		t.Fatal(err)
	}
	if changed.RingDigest == original.RingDigest {
		t.Fatal("fixture did not change ring")
	}
	if !changed.Nym.Equal(&original.Nym) || !changed.S.Equal(&original.S) {
		t.Fatal("same user/issue/counter should remain linkable across rings/accounts")
	}
	if changed.R.Cmp(original.R) == 0 {
		t.Fatal("transcript must differ")
	}
	// Counter reuse is a tracing condition even before k+1 messages exist.
	if original.K <= 2 {
		t.Fatal("fixture must leave unused counter slots")
	}
	var left, right, recovered secp256k1.G1Affine
	left.ScalarMultiplication(&original.T, changed.R)
	right.ScalarMultiplication(&changed.T, original.R)
	recovered.Sub(&left, &right)
	inverse := new(big.Int).ModInverse(new(big.Int).Sub(changed.R, original.R), fr.Modulus())
	recovered.ScalarMultiplication(&recovered, inverse)
	want, err := TraceKey(w.X)
	if err != nil || !recovered.Equal(&want) {
		t.Fatal("early duplicate-counter trace did not recover user key", err)
	}
	otherIssue := sha256.Sum256([]byte("different issue"))
	separate, _, err := MakeStatement(p, otherRing, 1, w.X, accounts[2].D, otherIssue, changed.MessageDigest, 101, original.K, w.Counter)
	if err != nil {
		t.Fatal(err)
	}
	if separate.Nym.Equal(&original.Nym) || separate.S.Equal(&original.S) {
		t.Fatal("fixture issue separation failed")
	}
}
