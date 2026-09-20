package nativeproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestQSDHCeremony(t *testing.T) {
	const capacity = 4
	first, e := ContributeQSDH(capacity, nil)
	if e != nil {
		t.Fatal(e)
	}
	second, e := ContributeQSDH(capacity, [][]byte{first})
	if e != nil {
		t.Fatal(e)
	}
	beacon := sha256.Sum256([]byte("LOCAL REHEARSAL ONLY, NOT A PUBLIC BEACON"))
	chain := [][]byte{first, second}
	p, receipt, e := FinalizeQSDHCeremony(capacity, chain, beacon)
	if e != nil {
		t.Fatal(e)
	}
	again, other, e := FinalizeQSDHCeremony(capacity, chain, beacon)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := MarshalParams(p)
	raw2, _ := MarshalParams(again)
	if !bytes.Equal(raw, raw2) || receipt.ParametersSHA256 != other.ParametersSHA256 {
		t.Fatal("nonreproducible ceremony verification")
	}
	a, _, e := KeyGen(nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _, e := KeyGen(nil)
	if e != nil {
		t.Fatal(e)
	}
	ring := []Account{a, b}
	v, e := Accumulate(p, ring)
	if e != nil {
		t.Fatal(e)
	}
	w, e := MembershipWitness(p, ring, 0)
	if e != nil {
		t.Fatal(e)
	}
	m, _ := Member(a)
	if !VerifyMembership(p, v, w, m) {
		t.Fatal("ceremony parameters do not support membership")
	}
	for name, chain := range map[string][][]byte{"missing": nil, "single": {first}, "reordered": {second, first}, "duplicate": {first, first}, "truncated": {first, second[:len(second)-1]}} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := FinalizeQSDHCeremony(capacity, chain, beacon); e == nil {
				t.Fatal("invalid chain accepted")
			}
		})
	}
	corrupted := append([]byte{}, second...)
	corrupted[len(corrupted)-1] ^= 1
	if _, e = ContributeQSDH(capacity, [][]byte{first, corrupted}); e == nil {
		t.Fatal("unverified predecessor accepted")
	}
	huge := append([]byte{}, second...)
	binary.BigEndian.PutUint64(huge[288:296], ^uint64(0))
	if _, _, e = FinalizeQSDHCeremony(capacity, [][]byte{first, huge}, beacon); e == nil {
		t.Fatal("untrusted allocation size accepted")
	}
	if _, _, e = FinalizeQSDHCeremony(capacity+1, chain, beacon); e != nil { // capacities 4/5 share a domain; both are intentionally valid truncations
		t.Fatal("same domain truncation should be explicit in receipt", e)
	}
	if _, _, e = FinalizeQSDHCeremony(8, chain, beacon); e == nil {
		t.Fatal("wrong domain accepted")
	}
	if _, _, e = FinalizeQSDHCeremony(capacity, chain, [32]byte{}); e == nil {
		t.Fatal("missing beacon accepted")
	}
}
