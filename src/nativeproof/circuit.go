package nativeproof

// Circuit is the connected native research profile. Public ring membership is
// supplied as V and is recomputed by the host verifier from its trusted ring.
// The selected account, its handle, x, d, both seed hashes, counter and W are
// private. A q-SDH witness avoids revealing an account index or using an
// independent, unbound selector gadget.
import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type SecpPoint = sw_emulated.AffinePoint[emulated.Secp256k1Fp]
type SecpScalar = emulated.Element[emulated.Secp256k1Fr]

type Circuit struct {
	V, Nym                           sw_bn254.G1Affine `gnark:",public"`
	H, HTau                          sw_bn254.G2Affine `gnark:",public"`
	Ut, SPoint, TPoint               SecpPoint         `gnark:",public"`
	Issue, RingDigest, MessageDigest [32]uints.U8      `gnark:",public"`
	Timestamp, K                     frontend.Variable `gnark:",public"`
	R                                SecpScalar        `gnark:",public"`
	X, D                             SecpScalar
	AccountU, AccountY               SecpPoint
	W                                sw_bn254.G1Affine
	Counter                          frontend.Variable
}

func sha(api frontend.API, data []uints.U8) ([]uints.U8, error) {
	h, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(), nil
}

// Little-endian bits describe a single integer, NOT one native BN254 field
// element. This distinction matters for 256-bit secp values and SHA digests.
func bytesBits(api frontend.API, data []uints.U8) []frontend.Variable {
	out := make([]frontend.Variable, 0, len(data)*8)
	for i := len(data) - 1; i >= 0; i-- {
		out = append(out, api.ToBinary(data[i].Val, 8)...)
	}
	return out
}
func integerBytes(api frontend.API, bs []frontend.Variable, width int) []uints.U8 {
	padded := make([]frontend.Variable, 8*width)
	for i := range padded {
		padded[i] = 0
	}
	if len(bs) > len(padded) {
		panic("integer exceeds encoding width")
	}
	copy(padded, bs)
	out := make([]uints.U8, width)
	for i := 0; i < width; i++ {
		out[width-1-i] = uints.U8{Val: api.FromBinary(padded[i*8 : (i+1)*8]...)}
	}
	return out
}
func fieldBytes[T emulated.FieldParams](api frontend.API, f *emulated.Field[T], value *emulated.Element[T]) []uints.U8 {
	f.AssertIsInRange(value)
	return integerBytes(api, f.ToBitsCanonical(value), 32)
}
func nativeValue(api frontend.API, data []uints.U8) frontend.Variable {
	var out frontend.Variable = 0
	for _, b := range data {
		api.ToBinary(b.Val, 8)
		out = api.Add(api.Mul(out, 256), b.Val)
	}
	return out // exactly the integer modulo BN254 Fr, the circuit field
}
func secpValue(api frontend.API, f *emulated.Field[emulated.Secp256k1Fr], data []uints.U8) *SecpScalar {
	return f.ReduceStrict(f.FromBits(bytesBits(api, data)...))
}
func secpEncoding(api frontend.API, f *emulated.Field[emulated.Secp256k1Fp], p *SecpPoint) []uints.U8 {
	return append(fieldBytes(api, f, &p.X), fieldBytes(api, f, &p.Y)...)
}
func nonzeroPoint[T emulated.FieldParams](api frontend.API, f *emulated.Field[T], p *sw_emulated.AffinePoint[T]) {
	api.AssertIsEqual(api.Mul(f.IsZero(&p.X), f.IsZero(&p.Y)), 0)
}

func (c *Circuit) Define(api frontend.API) error {
	if api.Compiler().Field().Cmp(bn254.ID.ScalarField()) != 0 {
		return fmt.Errorf("native Lk-TRS circuit requires BN254 Fr")
	}
	sec, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	sfp, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return err
	}
	bfr, err := emulated.NewField[emulated.BN254Fr](api)
	if err != nil {
		return err
	}
	bfp, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return err
	}
	sc, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	bc, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	complete := algopts.WithCompleteArithmetic()
	for _, p := range []*SecpPoint{&c.Ut, &c.SPoint, &c.TPoint, &c.AccountU, &c.AccountY} {
		sc.AssertIsOnCurve(p)
		nonzeroPoint(api, sfp, p)
	}
	for _, p := range []*sw_bn254.G1Affine{&c.V, &c.W, &c.Nym} {
		pairing.AssertIsOnG1(p)
		nonzeroPoint(api, bfp, p)
	}
	for _, p := range []*sw_bn254.G2Affine{&c.H, &c.HTau} {
		pairing.AssertIsOnG2(p)
		z := api.Mul(bfp.IsZero(&p.P.X.A0), bfp.IsZero(&p.P.X.A1), bfp.IsZero(&p.P.Y.A0), bfp.IsZero(&p.P.Y.A1))
		api.AssertIsEqual(z, 0)
	}
	sec.AssertIsInRange(&c.X)
	sec.AssertIsDifferent(&c.X, sec.Zero())
	sec.AssertIsInRange(&c.D)
	sec.AssertIsDifferent(&c.D, sec.Zero())
	sec.AssertIsInRange(&c.R)
	sec.AssertIsDifferent(&c.R, sec.Zero())
	cntBits := api.ToBinary(c.Counter, 32)
	api.ToBinary(c.K, 32)
	api.AssertIsDifferent(c.K, 0)
	api.ToBinary(api.Sub(c.K, c.Counter, 1), 32) // cnt < k, no field wrap with 32-bit operands
	cnt := sec.FromBits(cntBits...)
	xbytes := fieldBytes(api, sec, &c.X)
	seedMessage := append(append([]uints.U8{}, xbytes...), c.Issue[:]...)
	sh, err := sha(api, append(append([]uints.U8{}, seedMessage...), uints.NewU8(0)))
	if err != nil {
		return err
	}
	th, err := sha(api, append(append([]uints.U8{}, seedMessage...), uints.NewU8(1)))
	if err != nil {
		return err
	}
	s := secpValue(api, sec, sh)
	t := secpValue(api, sec, th)
	sec.AssertIsDifferent(s, sec.Zero())
	sec.AssertIsDifferent(t, sec.Zero())
	// Paper nym stays in pairing G1; canonical secp integers are explicitly
	// reduced into BN254 Fr for these exponents only.
	xbn := bfr.FromBits(api.ToBinary(nativeValue(api, xbytes))...)
	sbn := bfr.FromBits(api.ToBinary(nativeValue(api, fieldBytes(api, sec, s)))...)
	tbn := bfr.FromBits(api.ToBinary(nativeValue(api, fieldBytes(api, sec, t)))...)
	g := make([]sw_bn254.G1Affine, 3)
	for i, label := range []string{"g0", "g1", "g2"} {
		p, e := bn254.HashToG1([]byte(label), []byte("LKTRS-BN254-NYM-V1"))
		if e != nil {
			return e
		}
		g[i] = sw_bn254.NewG1Affine(p)
	}
	nym := bc.AddUnified(bc.ScalarMul(&g[0], sbn, complete), bc.ScalarMul(&g[1], tbn, complete))
	nym = bc.AddUnified(nym, bc.ScalarMul(&g[2], xbn, complete))
	bc.AssertIsEqual(nym, &c.Nym)
	// Account ownership and the hash entering the pairing relation share the
	// very same private points. No disconnected account bytes or selector.
	sc.AssertIsEqual(sc.ScalarMulBase(&c.D, complete), &c.AccountU)
	sc.AssertIsEqual(sc.ScalarMul(&c.AccountU, &c.X, complete), &c.AccountY)
	memberInput := uints.NewU8Array([]byte("lktrs/member/v1"))
	memberInput = append(memberInput, secpEncoding(api, sfp, &c.AccountU)...)
	memberInput = append(memberInput, secpEncoding(api, sfp, &c.AccountY)...)
	mh, err := sha(api, memberInput)
	if err != nil {
		return err
	}
	aNative := nativeValue(api, mh)
	api.AssertIsDifferent(aNative, 0)
	a := bfr.FromBits(api.ToBinary(aNative)...)
	// e(W,aH+HTau)=e(V,H), regrouped to two pairings using G1 scalar mul.
	aWminusV := bc.AddUnified(bc.ScalarMul(&c.W, a, complete), bc.Neg(&c.V))
	if err = pairing.PairingCheck([]*sw_bn254.G1Affine{aWminusV, &c.W}, []*sw_bn254.G2Affine{&c.H, &c.HTau}); err != nil {
		return fmt.Errorf("q-SDH: %w", err)
	}
	transcript := uints.NewU8Array([]byte("lktrs/challenge/v1"))
	transcript = append(transcript, c.Issue[:]...)
	transcript = append(transcript, c.RingDigest[:]...)
	transcript = append(transcript, c.MessageDigest[:]...)
	transcript = append(transcript, fieldBytes(api, bfp, &c.Nym.X)...)
	transcript = append(transcript, fieldBytes(api, bfp, &c.Nym.Y)...)
	transcript = append(transcript, integerBytes(api, api.ToBinary(c.Timestamp, 64), 8)...)
	transcript = append(transcript, integerBytes(api, api.ToBinary(c.K, 32), 4)...)
	rh, err := sha(api, transcript)
	if err != nil {
		return err
	}
	r := secpValue(api, sec, rh)
	sec.AssertIsEqual(r, &c.R)
	denS := sec.Add(sec.Add(s, cnt), sec.One())
	sec.AssertIsDifferent(denS, sec.Zero())
	sc.AssertIsEqual(sc.ScalarMul(&c.Ut, sec.Inverse(denS), complete), &c.SPoint)
	denT := sec.Add(sec.Add(t, cnt), sec.One())
	sec.AssertIsDifferent(denT, sec.Zero())
	tp := sc.AddUnified(sc.ScalarMulBase(&c.X, complete), sc.ScalarMul(&c.Ut, sec.Mul(r, sec.Inverse(denT)), complete))
	sc.AssertIsEqual(tp, &c.TPoint)
	return nil
}
