package nativeproof

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// T relation in a native standalone group:
//
//	T^(t+cnt+1) = (u^x)^(t+cnt+1) * u_t^R.
//
// The circuit uses additive point notation for secp256k1.
type tRelationCircuit struct {
	U    sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	UT   sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	T    sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	X    emulated.Element[emulated.Secp256k1Fr]
	TExp emulated.Element[emulated.Secp256k1Fr]
	Cnt  emulated.Element[emulated.Secp256k1Fr]
	R    emulated.Element[emulated.Secp256k1Fr] `gnark:",public"`
}

func (c *tRelationCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](
		api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	den := f.Add(&c.TExp, &c.Cnt)
	den = f.Add(den, f.One())
	f.AssertIsDifferent(den, f.Zero())
	left := curve.ScalarMul(&c.T, den, algopts.WithCompleteArithmetic())
	right := curve.ScalarMul(&c.U, f.Mul(den, &c.X), algopts.WithCompleteArithmetic())
	right = curve.AddUnified(right, curve.ScalarMul(&c.UT, &c.R, algopts.WithCompleteArithmetic()))
	curve.AssertIsEqual(left, right)
	return nil
}

func TestTRelation(t *testing.T) {
	_, generator := secp256k1.Generators()
	point := func(mult int64) secp256k1.G1Affine {
		var result secp256k1.G1Affine
		result.ScalarMultiplication(&generator, big.NewInt(mult))
		return result
	}
	toCircuit := secpPoint
	u, ut := point(11), point(19)
	x, tt, cnt, r := int64(3), int64(7), int64(2), int64(13)
	den := new(big.Int).Add(big.NewInt(tt), big.NewInt(cnt))
	den.Add(den, big.NewInt(1))
	modulus := secp256k1.ID.ScalarField()
	var ux secp256k1.G1Affine
	ux.ScalarMultiplication(&u, big.NewInt(x))
	invDen := new(big.Int).ModInverse(den, modulus)
	if invDen == nil {
		t.Fatal("honest fixture has a zero denominator")
	}
	// Paper relation: T = x*U + (R/den)*UT. Only the masking term
	// is divided by den; dividing x*U as well breaks public extraction.
	tag := func(challenge int64) secp256k1.G1Affine {
		rOverDen := new(big.Int).Mul(big.NewInt(challenge), invDen)
		rOverDen.Mod(rOverDen, modulus)
		var mask, result secp256k1.G1Affine
		mask.ScalarMultiplication(&ut, rOverDen)
		result.Add(&ux, &mask)
		return result
	}
	tPoint := tag(r)
	toScalar := func(v int64) emulated.Element[emulated.Secp256k1Fr] {
		return emulated.ValueOf[emulated.Secp256k1Fr](secfr.NewElement(uint64(v)))
	}
	witness := tRelationCircuit{
		U: toCircuit(u), UT: toCircuit(ut), T: toCircuit(tPoint),
		X: toScalar(x), TExp: toScalar(tt), Cnt: toScalar(cnt), R: toScalar(r),
	}
	circuit := tRelationCircuit{}
	if err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	// The former fixture and constraint accepted (x*U + R*UT)/den.
	// Keep that exact false positive as a regression, with den != 1.
	var mask, numerator, wrongT secp256k1.G1Affine
	mask.ScalarMultiplication(&ut, big.NewInt(r))
	numerator.Add(&ux, &mask)
	wrongT.ScalarMultiplication(&numerator, invDen)
	if wrongT.Equal(&tPoint) {
		t.Fatal("wrong-formula fixture coincides with the paper tag")
	}
	wrongFormula := witness
	wrongFormula.T = toCircuit(wrongT)
	if err := test.IsSolved(&circuit, &wrongFormula, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("old incorrect T=(x*U+R*UT)/den accepted")
	}

	// Both tags reuse the same (t,cnt), and therefore the same den.
	// In native group algebra the public extraction must recover x*U:
	// (R2*T1 - R1*T2)/(R2-R1) = x*U.
	r2 := int64(17)
	tPoint2 := tag(r2)
	second := witness
	second.T, second.R = toCircuit(tPoint2), toScalar(r2)
	if err := test.IsSolved(&circuit, &second, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("second honest repeat-counter tag rejected: %v", err)
	}
	var firstWeighted, secondWeighted, difference, recovered secp256k1.G1Affine
	firstWeighted.ScalarMultiplication(&tPoint, big.NewInt(r2))
	secondWeighted.ScalarMultiplication(&tPoint2, big.NewInt(r))
	difference.Sub(&firstWeighted, &secondWeighted)
	invChallengeDifference := new(big.Int).ModInverse(big.NewInt(r2-r), modulus)
	if invChallengeDifference == nil {
		t.Fatal("trace fixture repeats its challenge")
	}
	recovered.ScalarMultiplication(&difference, invChallengeDifference)
	if !recovered.Equal(&ux) {
		t.Fatal("correct repeat-counter tags did not trace to x*U")
	}
	bad := witness
	bad.T = toCircuit(point(23))
	if err := test.IsSolved(&circuit, &bad, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("mutated T accepted")
	}
	badChallenge := witness
	badChallenge.R = toScalar(14)
	if err := test.IsSolved(&circuit, &badChallenge, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("mutated R accepted")
	}
	// With den = 0 and R = 0 the multiplied equation alone degenerates
	// to 0 = 0 for any T. The explicit nonzero check must reject it.
	zeroDen := witness
	zeroCnt := new(big.Int).Sub(modulus, big.NewInt(tt+1))
	zeroDen.Cnt = emulated.ValueOf[emulated.Secp256k1Fr](zeroCnt)
	zeroDen.R = toScalar(0)
	if err := test.IsSolved(&circuit, &zeroDen, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("zero denominator accepted")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("constraints %d", cs.GetNbConstraints())
}
