package nativeproof

import (
	"bytes"
	"encoding/binary"
	bn "github.com/consensys/gnark-crypto/ecc/bn254"
	groth "github.com/consensys/gnark/backend/groth16/bn254"
	"testing"
)

func TestProofDecoderPreflight(t *testing.T) {
	_, _, g, h := bn.Generators()
	// This only tests the binary layout; it is not a valid Groth16 proof.
	p := groth.Proof{Ar: g, Bs: h, Krs: g, Commitments: []bn.G1Affine{g}, CommitmentPok: g}
	var b bytes.Buffer
	if _, e := p.WriteTo(&b); e != nil {
		t.Fatal(e)
	}
	good := b.Bytes()
	if e := preflightProof(good, 1); e != nil {
		t.Fatal(e)
	}
	const offset = 2*bn.SizeOfG1AffineCompressed + bn.SizeOfG2AffineCompressed
	for _, n := range []uint32{0, 2, 1 << 20, ^uint32(0)} {
		bad := append([]byte{}, good...)
		binary.BigEndian.PutUint32(bad[offset:offset+4], n)
		if preflightProof(bad, 1) == nil {
			t.Fatalf("untrusted commitment count %d accepted", n)
		}
	}
	for _, at := range []int{0, 32, 96, 132, 164} {
		bad := append([]byte{}, good...)
		bad[at] &= 0x3f
		if preflightProof(bad, 1) == nil {
			t.Fatalf("raw point marker at %d accepted", at)
		}
	}
	if preflightProof(append(append([]byte{}, good...), 0), 1) == nil {
		t.Fatal("extra bytes accepted")
	}
	if preflightProof(good[:len(good)-1], 1) == nil {
		t.Fatal("truncation accepted")
	}
}
