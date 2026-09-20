package nativeproof

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

// Exact witness-to-q-SDH reduction identity, also demonstrating that an
// algebraically valid SRS is forgeable by somebody retaining tau. This test is
// arithmetic evidence, not evidence that q-SDH is hard or a ceremony honest.
func TestMembershipReductionAndKnownTrapdoor(t *testing.T) {
	mod := bnfr.Modulus()
	tau := big.NewInt(1234567)
	_, _, g, h := bn254.Generators()
	p := Params{G: g, H: h, Powers: make([]bn254.G1Affine, 5)}
	p.HTau.ScalarMultiplication(&h, tau)
	power := big.NewInt(1)
	for i := range p.Powers {
		p.Powers[i].ScalarMultiplication(&g, power)
		power.Mul(power, tau).Mod(power, mod)
	}
	if e := ValidateParams(p); e != nil {
		t.Fatal(e)
	}
	members := []*big.Int{big.NewInt(11), big.NewInt(23), big.NewInt(37)}
	b := big.NewInt(41)
	v, e := combinePowers(p, members)
	if e != nil {
		t.Fatal(e)
	}
	inverse := new(big.Int).ModInverse(new(big.Int).Add(tau, b), mod)
	var forged bn254.G1Affine
	forged.ScalarMultiplication(&v, inverse)
	if !VerifyMembership(p, v, forged, b) {
		t.Fatal("retained trapdoor counterexample failed")
	}
	// F(X)=(X+b)Q(X)+F(-b), so (W-[Q(tau)]G)/F(-b)=[1/(tau+b)]G.
	coefficients := memberPolynomial(members)
	n := len(coefficients) - 1
	q := make([]*big.Int, n)
	q[n-1] = newBig(coefficients[n])
	for i := n - 2; i >= 0; i-- {
		q[i] = new(big.Int).Sub(coefficients[i+1], new(big.Int).Mul(b, q[i+1]))
		q[i].Mod(q[i], mod)
	}
	remainder := new(big.Int).Sub(coefficients[0], new(big.Int).Mul(b, q[0]))
	remainder.Mod(remainder, mod)
	var quotient bn254.G1Affine
	quotient.SetInfinity()
	for i, c := range q {
		var term bn254.G1Affine
		term.ScalarMultiplication(&p.Powers[i], c)
		quotient.Add(&quotient, &term)
	}
	var extracted, want bn254.G1Affine
	extracted.Sub(&forged, &quotient)
	extracted.ScalarMultiplication(&extracted, new(big.Int).ModInverse(remainder, mod))
	want.ScalarMultiplication(&g, inverse)
	if !extracted.Equal(&want) {
		t.Fatal("polynomial q-SDH extraction identity failed")
	}
}
func TestDualOrderReductionIsNotScalarEquality(t *testing.T) {
	x := big.NewInt(7)
	alias := new(big.Int).Add(x, bnfr.Modulus())
	if alias.Cmp(secfr.Modulus()) >= 0 {
		t.Fatal("invalid alias fixture")
	}
	if new(big.Int).Mod(alias, bnfr.Modulus()).Cmp(x) != 0 {
		t.Fatal("reduction fixture")
	}
	issue := sha256.Sum256([]byte("alias issue"))
	s, tSeed, e := Seeds(x, issue)
	if e != nil {
		t.Fatal(e)
	}
	as, at, e := Seeds(alias, issue)
	if e != nil {
		t.Fatal(e)
	}
	if s.Cmp(as) == 0 || tSeed.Cmp(at) == 0 {
		t.Fatal("canonical secp integers were aliased before hashing")
	}
	a, _ := TraceKey(x)
	b, _ := TraceKey(alias)
	if a.Equal(&b) {
		t.Fatal("trace key order collapsed into BN254")
	}
}
