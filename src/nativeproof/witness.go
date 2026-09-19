package nativeproof

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

func secpPoint(p secp256k1.G1Affine) SecpPoint {
	return SecpPoint{X: emulated.ValueOf[emulated.Secp256k1Fp](p.X), Y: emulated.ValueOf[emulated.Secp256k1Fp](p.Y)}
}

// PublicAssignment requires no private witness, user database or signing key.
func PublicAssignment(p Params, st Statement) (*Circuit, error) {
	if st.R == nil {
		return nil, errors.New("missing challenge")
	}
	ut, err := IssueBase(st.Issue)
	if err != nil {
		return nil, err
	}
	c := &Circuit{V: sw_bn254.NewG1Affine(st.V), Nym: sw_bn254.NewG1Affine(st.Nym),
		H: sw_bn254.NewG2Affine(p.H), HTau: sw_bn254.NewG2Affine(p.HTau),
		Ut: secpPoint(ut), SPoint: secpPoint(st.S), TPoint: secpPoint(st.T),
		Timestamp: st.Timestamp, K: st.K, R: emulated.ValueOf[emulated.Secp256k1Fr](st.R)}
	copy(c.Issue[:], uints.NewU8Array(st.Issue[:]))
	copy(c.RingDigest[:], uints.NewU8Array(st.RingDigest[:]))
	copy(c.MessageDigest[:], uints.NewU8Array(st.MessageDigest[:]))
	return c, nil
}
func Assignment(p Params, st Statement, w SecretWitness) (*Circuit, error) {
	if w.X == nil || w.D == nil {
		return nil, errors.New("missing secret")
	}
	c, err := PublicAssignment(p, st)
	if err != nil {
		return nil, err
	}
	c.X = emulated.ValueOf[emulated.Secp256k1Fr](w.X)
	c.D = emulated.ValueOf[emulated.Secp256k1Fr](w.D)
	c.AccountU = secpPoint(w.Account.U)
	c.AccountY = secpPoint(w.Account.Y)
	c.W = sw_bn254.NewG1Affine(w.W)
	c.Counter = w.Counter
	return c, nil
}
