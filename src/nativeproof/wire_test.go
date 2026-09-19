package nativeproof

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"testing"
)

func TestNativeEnvelope(t *testing.T) {
	_, _, st, _ := fixture(t)
	s := Signed{st, Proof{Version: CircuitVersion, Data: []byte{1, 2, 3}}}
	raw, e := MarshalSigned(s)
	if e != nil {
		t.Fatal(e)
	}
	v, e := UnmarshalSigned(raw)
	if e != nil {
		t.Fatal(e)
	}
	again, e := MarshalSigned(v)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("noncanonical roundtrip")
	}
	// Every truncation is rejected before an allocation or point decode can
	// overread the fixed header. The dummy proof is not claimed valid here.
	for n := 0; n < len(raw); n++ {
		if _, e = UnmarshalSigned(raw[:n]); e == nil {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	if _, e = UnmarshalSigned(append(append([]byte{}, raw...), 0)); e == nil {
		t.Fatal("trailing data accepted")
	}
	bad := append([]byte{}, raw...)
	bad[0] ^= 1
	if _, e = UnmarshalSigned(bad); e == nil {
		t.Fatal("version mismatch accepted")
	}
	bad = append([]byte{}, raw...)
	off := 8 + 32*3 + 64*4 + 8 + 4
	fr.Modulus().FillBytes(bad[off : off+32])
	if _, e = UnmarshalSigned(bad); e == nil {
		t.Fatal("unreduced challenge accepted")
	}
	// noncanonical first BN point coordinate: prime-field decoders reject
	// all-ones rather than reducing it to another point.
	bad = append([]byte{}, raw...)
	for i := 8 + 32*3; i < 8+32*3+32; i++ {
		bad[i] = 255
	}
	if _, e = UnmarshalSigned(bad); e == nil {
		t.Fatal("invalid curve bytes accepted")
	}
}
