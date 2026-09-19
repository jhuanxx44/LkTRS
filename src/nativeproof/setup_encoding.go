package nativeproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/constraint"
)

const paramsMagic = "LKTRSP01"
const maxParamsBytes = 12 + 32 + 64*2 + ((1<<16)+1)*32

// MarshalParams writes only the public q-SDH powers, never the trapdoor.
func MarshalParams(p Params) ([]byte, error) {
	if err := ValidateParams(p); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(paramsMagic)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(p.Powers)))
	g, h, ht := p.G.Bytes(), p.H.Bytes(), p.HTau.Bytes()
	b.Write(g[:])
	b.Write(h[:])
	b.Write(ht[:])
	for _, v := range p.Powers {
		enc := v.Bytes()
		b.Write(enc[:])
	}
	return b.Bytes(), nil
}

func UnmarshalParams(raw []byte) (Params, error) {
	var p Params
	if len(raw) < 12 || len(raw) > maxParamsBytes || string(raw[:8]) != paramsMagic {
		return p, errors.New("invalid public parameter header")
	}
	count := binary.BigEndian.Uint32(raw[8:12])
	if count < 2 || count > (1<<16)+1 || uint64(len(raw)) != 12+32+128+uint64(count)*32 {
		return p, errors.New("invalid public power count or size")
	}
	pos := 12
	g1 := func(out *bn254.G1Affine) error {
		data := raw[pos : pos+32]
		pos += 32
		if _, err := out.SetBytes(data); err != nil {
			return err
		}
		enc := out.Bytes()
		if !bytes.Equal(data, enc[:]) || !goodBN(*out) {
			return errors.New("noncanonical public G1")
		}
		return nil
	}
	g2 := func(out *bn254.G2Affine) error {
		data := raw[pos : pos+64]
		pos += 64
		if _, err := out.SetBytes(data); err != nil {
			return err
		}
		enc := out.Bytes()
		if !bytes.Equal(data, enc[:]) || !goodBN2(*out) {
			return errors.New("noncanonical public G2")
		}
		return nil
	}
	if err := g1(&p.G); err != nil {
		return p, err
	}
	if err := g2(&p.H); err != nil {
		return p, err
	}
	if err := g2(&p.HTau); err != nil {
		return p, err
	}
	p.Powers = make([]bn254.G1Affine, int(count))
	for i := range p.Powers {
		if err := g1(&p.Powers[i]); err != nil {
			return Params{}, err
		}
	}
	if err := ValidateParams(p); err != nil {
		return Params{}, err
	}
	return p, nil
}

// preflightProvingKey validates every allocation-driving field in the pinned
// gnark compressed PK format before its decoder allocates or computes FFTs.
// Exact domain and wire limits come from the locally compiled circuit.
func preflightProvingKey(raw []byte, cs constraint.ConstraintSystem) error {
	const domainSize = 8 + 5*32 + 1
	domain := fft.NewDomain(uint64(cs.GetNbConstraints()), fft.WithoutPrecompute())
	var expected bytes.Buffer
	if _, err := domain.WriteTo(&expected); err != nil {
		return err
	}
	if len(raw) < domainSize || !bytes.Equal(raw[:domainSize-1], expected.Bytes()[:domainSize-1]) || raw[domainSize-1] > 1 {
		return errors.New("PK FFT domain differs from circuit")
	}
	wires := cs.GetNbPublicVariables() + cs.GetNbSecretVariables() + cs.GetNbInternalVariables()
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return errors.New("unsupported commitments")
	}
	pos := domainSize
	take := func(n int) ([]byte, error) {
		if n < 0 || n > len(raw)-pos {
			return nil, errors.New("truncated proving key")
		}
		b := raw[pos : pos+n]
		pos += n
		return b, nil
	}
	u32 := func() (int, error) {
		b, e := take(4)
		if e != nil {
			return 0, e
		}
		return int(binary.BigEndian.Uint32(b)), nil
	}
	u64 := func() (uint64, error) {
		b, e := take(8)
		if e != nil {
			return 0, e
		}
		return binary.BigEndian.Uint64(b), nil
	}
	points := func(n, width int) error {
		if n < 0 || n > (len(raw)-pos)/width {
			return errors.New("unsafe PK point count")
		}
		b, e := take(n * width)
		if e != nil {
			return e
		}
		for i := 0; i < len(b); i += width {
			if b[i]&0xc0 == 0 {
				return errors.New("uncompressed PK point forbidden")
			}
		}
		return nil
	}
	vector := func(width, max int) (int, error) {
		n, e := u32()
		if e != nil || n > max {
			return 0, errors.New("unsafe PK vector length")
		}
		return n, points(n, width)
	}
	if err := points(3, 32); err != nil {
		return err
	}
	na, e := vector(32, wires)
	if e != nil {
		return e
	}
	nb, e := vector(32, wires)
	if e != nil {
		return e
	}
	nz, e := vector(32, int(ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints()))))
	if e != nil {
		return e
	}
	private := cs.GetNbSecretVariables() + cs.GetNbInternalVariables() - len(commitments)
	for _, c := range commitments {
		private -= len(c.PrivateCommitted)
	}
	nk, e := vector(32, wires)
	if e != nil {
		return e
	}
	if nk != private || nz != int(domain.Cardinality)-1 {
		return errors.New("PK private or quotient vector differs from circuit")
	}
	if e = points(2, 64); e != nil {
		return e
	}
	nb2, e := vector(64, wires)
	if e != nil {
		return e
	}
	nw, e := u64()
	if e != nil || nw != uint64(wires) {
		return errors.New("PK wire count differs from circuit")
	}
	ia, e := u64()
	if e != nil || ia > nw {
		return errors.New("invalid PK infinity count")
	}
	ib, e := u64()
	if e != nil || ib > nw {
		return errors.New("invalid PK infinity count")
	}
	if na != wires-int(ia) || nb != wires-int(ib) || nb2 != nb {
		return errors.New("inconsistent PK point vectors")
	}
	for _, n := range []uint64{ia, ib} {
		b, e := take(wires)
		if e != nil {
			return e
		}
		var count uint64
		for _, v := range b {
			if v > 1 {
				return errors.New("invalid PK infinity flag")
			}
			count += uint64(v)
		}
		if count != n {
			return errors.New("PK infinity flags mismatch")
		}
	}
	nc, e := u32()
	if e != nil || nc != len(commitments) {
		return errors.New("PK commitment count differs from circuit")
	}
	for i := 0; i < nc; i++ {
		a, e := vector(32, wires)
		if e != nil {
			return e
		}
		b, e := vector(32, wires)
		if e != nil {
			return e
		}
		if a != b || a != len(commitments[i].PrivateCommitted) {
			return fmt.Errorf("PK commitment basis %d differs from circuit", i)
		}
	}
	if pos != len(raw) {
		return errors.New("trailing proving key bytes")
	}
	return nil
}
