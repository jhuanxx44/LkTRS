package nativeproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"io"
	"math/big"
)

// Fixed-width public signature envelope. No witness, member index, account
// identity or seed digest is part of this encoding.
const signatureMagic = "LKTRSN01"
const statementWireBytes = 32*3 + 64*4 + 8 + 4 + 32
const signaturePrefixBytes = 8 + statementWireBytes + 32*2 + 4

func MarshalSigned(s Signed) ([]byte, error) {
	st := s.Statement
	if s.Proof.Version != CircuitVersion || len(s.Proof.Data) == 0 || len(s.Proof.Data) > maxProofBytes {
		return nil, errors.New("invalid proof envelope")
	}
	if !goodBN(st.V) || !goodBN(st.Nym) || !goodSecp(st.S) || !goodSecp(st.T) || !canonicalNonzero(st.R, fr.Modulus()) || st.K == 0 {
		return nil, errors.New("invalid signature fields")
	}
	b := bytes.NewBuffer(make([]byte, 0, signaturePrefixBytes+len(s.Proof.Data)))
	b.WriteString(signatureMagic)
	b.Write(st.Issue[:])
	b.Write(st.RingDigest[:])
	b.Write(st.MessageDigest[:])
	b.Write(EncodeBNPoint(st.V))
	b.Write(EncodeBNPoint(st.Nym))
	b.Write(EncodeSecpPoint(st.S))
	b.Write(EncodeSecpPoint(st.T))
	binary.Write(b, binary.BigEndian, st.Timestamp)
	binary.Write(b, binary.BigEndian, st.K)
	var r [32]byte
	st.R.FillBytes(r[:])
	b.Write(r[:])
	b.Write(s.Proof.CircuitHash[:])
	b.Write(s.Proof.KeyID[:])
	binary.Write(b, binary.BigEndian, uint32(len(s.Proof.Data)))
	b.Write(s.Proof.Data)
	return b.Bytes(), nil
}
func readBN(r io.Reader) (bn254.G1Affine, error) {
	var enc [64]byte
	var p bn254.G1Affine
	if _, err := io.ReadFull(r, enc[:]); err != nil {
		return p, err
	}
	if err := p.X.SetBytesCanonical(enc[:32]); err != nil {
		return p, err
	}
	if err := p.Y.SetBytesCanonical(enc[32:]); err != nil {
		return p, err
	}
	if !goodBN(p) {
		return p, errors.New("invalid BN254 point")
	}
	return p, nil
}
func readSecp(r io.Reader) (secp256k1.G1Affine, error) {
	var enc [64]byte
	var p secp256k1.G1Affine
	if _, err := io.ReadFull(r, enc[:]); err != nil {
		return p, err
	}
	if err := p.X.SetBytesCanonical(enc[:32]); err != nil {
		return p, err
	}
	if err := p.Y.SetBytesCanonical(enc[32:]); err != nil {
		return p, err
	}
	if !goodSecp(p) {
		return p, errors.New("invalid secp256k1 point")
	}
	return p, nil
}
func UnmarshalSigned(raw []byte) (Signed, error) {
	var out Signed
	if len(raw) < signaturePrefixBytes || len(raw) > signaturePrefixBytes+maxProofBytes {
		return out, errors.New("invalid signature length")
	}
	r := bytes.NewReader(raw)
	magic := make([]byte, 8)
	io.ReadFull(r, magic)
	if string(magic) != signatureMagic {
		return out, errors.New("invalid profile magic/version")
	}
	io.ReadFull(r, out.Statement.Issue[:])
	io.ReadFull(r, out.Statement.RingDigest[:])
	io.ReadFull(r, out.Statement.MessageDigest[:])
	var err error
	out.Statement.V, err = readBN(r)
	if err != nil {
		return out, err
	}
	out.Statement.Nym, err = readBN(r)
	if err != nil {
		return out, err
	}
	out.Statement.S, err = readSecp(r)
	if err != nil {
		return out, err
	}
	out.Statement.T, err = readSecp(r)
	if err != nil {
		return out, err
	}
	binary.Read(r, binary.BigEndian, &out.Statement.Timestamp)
	binary.Read(r, binary.BigEndian, &out.Statement.K)
	var rb [32]byte
	io.ReadFull(r, rb[:])
	out.Statement.R = new(big.Int).SetBytes(rb[:])
	if !canonicalNonzero(out.Statement.R, fr.Modulus()) || out.Statement.K == 0 {
		return out, errors.New("noncanonical challenge or quota")
	}
	io.ReadFull(r, out.Proof.CircuitHash[:])
	io.ReadFull(r, out.Proof.KeyID[:])
	out.Proof.Version = CircuitVersion
	var n uint32
	binary.Read(r, binary.BigEndian, &n)
	if n == 0 || int(n) != r.Len() {
		return out, errors.New("truncated or trailing proof")
	}
	out.Proof.Data = make([]byte, n)
	io.ReadFull(r, out.Proof.Data)
	return out, nil
}
