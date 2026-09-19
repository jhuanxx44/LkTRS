package nativeproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bncurve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/backend/groth16"
	bngroth "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"io"
	"math/big"
	"reflect"
	"sync"
)

const CircuitVersion = "lktrs-native-bn254-secp256k1-v1"
const maxProofBytes = 1 << 20

// ExpectedCircuitHash is derived from gnark's canonical serialized R1CS, not
// from a human-maintained version label. Callers should treat the returned
// digest as a profile identity and still authenticate the setup manifest that
// binds it to a VK and ceremony artifact.
func ExpectedCircuitHash() ([32]byte, error) {
	cs, err := Compile()
	if err != nil {
		return [32]byte{}, err
	}
	return digestWriter(cs)
}

type Proof struct {
	Version            string
	CircuitHash, KeyID [32]byte
	Data               []byte
}
type Signed struct {
	Statement Statement
	Proof     Proof
}
type Prover struct {
	mu                 sync.Mutex
	cs                 constraint.ConstraintSystem
	pk                 groth16.ProvingKey
	circuitHash, keyID [32]byte
}
type Verifier struct {
	vk                 groth16.VerifyingKey
	circuitHash, keyID [32]byte
}

type VerificationContext struct {
	params   Params
	accounts []Account
	issue    [32]byte
	k        uint32
	vDigest  [32]byte
}

func NewVerificationContext(p Params, accounts []Account, issue [32]byte, k uint32) (VerificationContext, error) {
	if k == 0 {
		return VerificationContext{}, errors.New("zero quota")
	}
	if err := ValidateParams(p); err != nil {
		return VerificationContext{}, err
	}
	if _, err := Accumulate(p, accounts); err != nil {
		return VerificationContext{}, err
	}
	rd, err := RingDigest(accounts)
	if err != nil {
		return VerificationContext{}, err
	}
	return VerificationContext{cloneParams(p), cloneAccounts(accounts), issue, k, rd}, nil
}

// Compile circuit once. The circuit has no dependence on ring size or issue.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
func digestWriter(w io.WriterTo) ([32]byte, error) {
	h := sha256.New()
	if _, err := w.WriteTo(h); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// NewBackend performs local single-party Groth16 setup. This is a research
// setup, not an MPC ceremony; applications must distribute/trust its public VK.
func NewBackend() (*Prover, *Verifier, error) {
	cs, err := Compile()
	if err != nil {
		return nil, nil, err
	}
	circuitHash, err := digestWriter(cs)
	if err != nil {
		return nil, nil, fmt.Errorf("hash compiled circuit: %w", err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, nil, err
	}
	keyID, err := digestWriter(vk)
	if err != nil {
		return nil, nil, err
	}
	return &Prover{cs: cs, pk: pk, circuitHash: circuitHash, keyID: keyID}, &Verifier{vk: vk, circuitHash: circuitHash, keyID: keyID}, nil
}
func (p *Prover) Prove(params Params, st Statement, witness SecretWitness) (Signed, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, err := Assignment(params, st, witness)
	if err != nil {
		return Signed{}, err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return Signed{}, err
	}
	proof, err := groth16.Prove(p.cs, p.pk, w)
	if err != nil {
		return Signed{}, err
	}
	var buf bytes.Buffer
	if _, err = proof.WriteTo(&buf); err != nil {
		return Signed{}, err
	}
	// Statement owns its scalar, not a borrowed mutable signing pointer.
	st.R = newBig(st.R)
	return Signed{st, Proof{CircuitVersion, p.circuitHash, p.keyID, buf.Bytes()}}, nil
}
func (v *Verifier) KeyBytes() ([]byte, error) {
	var b bytes.Buffer
	_, err := v.vk.WriteTo(&b)
	return b.Bytes(), err
}

// The key and expected hashes must come from trusted setup, never from the
// candidate signature. This verifier carries no PK, witness or private registry.
func LoadVerifier(key []byte, circuitHash, keyID [32]byte) (*Verifier, error) {
	if len(key) > maxProofBytes {
		return nil, errors.New("oversized verifier key")
	}
	if sha256.Sum256(key) != keyID {
		return nil, errors.New("verification key digest mismatch")
	}
	if err := preflightVerifyingKey(key); err != nil {
		return nil, err
	}
	cs, err := Compile()
	if err != nil {
		return nil, err
	}
	return loadVerifierForCircuit(key, circuitHash, keyID, cs)
}

func loadVerifierForCircuit(key []byte, circuitHash, keyID [32]byte, cs constraint.ConstraintSystem) (*Verifier, error) {
	if len(key) > maxProofBytes || sha256.Sum256(key) != keyID {
		return nil, errors.New("verification key digest mismatch")
	}
	expectedHash, err := digestWriter(cs)
	if err != nil {
		return nil, err
	}
	if circuitHash != expectedHash {
		return nil, errors.New("circuit hash is not the compiled native profile")
	}
	if err := preflightVerifyingKey(key); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	r := bytes.NewReader(key)
	if _, err := vk.ReadFrom(r); err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing key bytes")
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return nil, errors.New("wrong circuit commitment type")
	}
	native := vk.(*bngroth.VerifyingKey)
	// gnark adds one verifier wire per commitment and omits the constant from
	// NbPublicWitness. Match the actual commitment layout, not an incidental
	// equality of that count with the number of circuit public variables.
	wantMetadata := commitments.GetPublicAndCommitmentCommitted(commitments.CommitmentIndexes(), cs.GetNbPublicVariables())
	if len(native.G1.K) != cs.GetNbPublicVariables()+len(commitments) ||
		len(native.CommitmentKeys) != len(commitments) ||
		!reflect.DeepEqual(native.PublicAndCommitmentCommitted, wantMetadata) {
		return nil, errors.New("verification key public/commitment layout differs from circuit")
	}
	return &Verifier{vk: vk, circuitHash: circuitHash, keyID: keyID}, nil
}

// Validate all variable-length prefixes before gnark's decoder, which otherwise
// allocates slices directly from untrusted uint32 counts. The native profile
// uses Pedersen commitments; exact metadata is checked against the local
// compiled circuit after decoding.
func preflightVerifyingKey(raw []byte) error {
	const maxEntries = 1 << 16
	pos := 0
	point := func(compressed, uncompressed int) error {
		if pos >= len(raw) {
			return errors.New("truncated verification key point")
		}
		size := uncompressed
		if raw[pos]&0xc0 != 0 {
			size = compressed
		}
		if size <= 0 || size > len(raw)-pos {
			return errors.New("invalid verification key point length")
		}
		pos += size
		return nil
	}
	readU32 := func() (uint32, error) {
		if len(raw)-pos < 4 {
			return 0, errors.New("truncated verification key length")
		}
		v := binary.BigEndian.Uint32(raw[pos : pos+4])
		pos += 4
		return v, nil
	}
	// [alpha]1, [beta]1, [beta]2, [gamma]2, [delta]1, [delta]2.
	for _, sizes := range [][2]int{
		{bncurve.SizeOfG1AffineCompressed, bncurve.SizeOfG1AffineUncompressed},
		{bncurve.SizeOfG1AffineCompressed, bncurve.SizeOfG1AffineUncompressed},
		{bncurve.SizeOfG2AffineCompressed, bncurve.SizeOfG2AffineUncompressed},
		{bncurve.SizeOfG2AffineCompressed, bncurve.SizeOfG2AffineUncompressed},
		{bncurve.SizeOfG1AffineCompressed, bncurve.SizeOfG1AffineUncompressed},
		{bncurve.SizeOfG2AffineCompressed, bncurve.SizeOfG2AffineUncompressed},
	} {
		if err := point(sizes[0], sizes[1]); err != nil {
			return err
		}
	}
	count, err := readU32()
	if err != nil || count > maxEntries {
		return errors.New("verification key public vector count is unsafe")
	}
	for i := uint32(0); i < count; i++ {
		if err := point(bncurve.SizeOfG1AffineCompressed, bncurve.SizeOfG1AffineUncompressed); err != nil {
			return err
		}
	}
	outer, err := readU32()
	if err != nil || outer > maxEntries {
		return errors.New("verification key metadata count is unsafe")
	}
	var total uint64
	for i := uint32(0); i < outer; i++ {
		inner, e := readU32()
		if e != nil || inner > maxEntries {
			return errors.New("verification key metadata width is unsafe")
		}
		total += uint64(inner)
		if total > 1<<20 || uint64(inner)*8 > uint64(len(raw)-pos) {
			return errors.New("verification key metadata oversized")
		}
		pos += int(inner) * 8
	}
	commitments, err := readU32()
	if err != nil {
		return err
	}
	if commitments > 64 {
		return errors.New("verification key commitment count is unsafe")
	}
	for i := uint32(0); i < commitments; i++ {
		// Each gnark BN254 Pedersen verifying key has two G2 points.
		for j := 0; j < 2; j++ {
			if err := point(bncurve.SizeOfG2AffineCompressed, bncurve.SizeOfG2AffineUncompressed); err != nil {
				return err
			}
		}
	}
	if pos != len(raw) {
		return errors.New("trailing verification key bytes")
	}
	return nil
}
func (v *Verifier) IDs() ([32]byte, [32]byte) { return v.circuitHash, v.keyID }

func (ctx VerificationContext) check(message []byte, st Statement) error {
	if st.Issue != ctx.issue || st.K != ctx.k {
		return errors.New("issue or quota mismatch")
	}
	if st.MessageDigest != sha256.Sum256(message) {
		return errors.New("message mismatch")
	}
	if st.RingDigest != ctx.vDigest {
		return errors.New("ring digest mismatch")
	}
	expected, err := Accumulate(ctx.params, ctx.accounts)
	if err != nil {
		return err
	}
	if !st.V.Equal(&expected) {
		return errors.New("ring accumulator mismatch")
	}
	if !goodBN(st.Nym) || !goodSecp(st.S) || !goodSecp(st.T) {
		return errors.New("invalid signature point")
	}
	if !canonicalNonzero(st.R, fr.Modulus()) {
		return errors.New("invalid challenge")
	}
	r, err := Challenge(st)
	if err != nil {
		return err
	}
	if r.Cmp(st.R) != 0 {
		return errors.New("transcript challenge mismatch")
	}
	return nil
}
func (v *Verifier) Verify(ctx VerificationContext, message []byte, signed Signed) error {
	if v == nil || v.vk == nil {
		return errors.New("missing verifier")
	}
	p := signed.Proof
	if p.Version != CircuitVersion || p.CircuitHash != v.circuitHash || p.KeyID != v.keyID {
		return errors.New("proof profile or key mismatch")
	}
	if err := ctx.check(message, signed.Statement); err != nil {
		return err
	}
	if len(p.Data) == 0 || len(p.Data) > maxProofBytes {
		return errors.New("invalid proof length")
	}
	nativeVK, ok := v.vk.(*bngroth.VerifyingKey)
	if !ok {
		return errors.New("wrong verifier curve")
	}
	if err := preflightProof(p.Data, len(nativeVK.CommitmentKeys)); err != nil {
		return err
	}
	proof := groth16.NewProof(ecc.BN254)
	r := bytes.NewReader(p.Data)
	if _, err := proof.ReadFrom(r); err != nil {
		return fmt.Errorf("proof encoding: %w", err)
	}
	if r.Len() != 0 {
		return errors.New("trailing proof bytes")
	}
	assignment, err := PublicAssignment(ctx.params, signed.Statement)
	if err != nil {
		return err
	}
	// The witness encoder must never request private values here.
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err = groth16.Verify(proof, v.vk, public); err != nil {
		return fmt.Errorf("proof rejected: %w", err)
	}
	return nil
}

func newBig(n *big.Int) *big.Int {
	if n == nil {
		return nil
	}
	return new(big.Int).Set(n)
}

// gnark's generic slice decoder allocates from the wire count before checking
// the remaining bytes. Only our compressed, fixed-layout format is permitted.
// Validate the count against TRUSTED VK metadata before calling that decoder.
func preflightProof(raw []byte, commitments int) error {
	const g1 = bncurve.SizeOfG1AffineCompressed
	const g2 = bncurve.SizeOfG2AffineCompressed
	const countOffset = 2*g1 + g2
	if commitments < 0 || commitments > (maxProofBytes-countOffset-4-g1)/g1 {
		return errors.New("invalid trusted commitment count")
	}
	expected := countOffset + 4 + g1*(commitments+1)
	if len(raw) != expected {
		return errors.New("wrong compressed proof size")
	}
	if binary.BigEndian.Uint32(raw[countOffset:countOffset+4]) != uint32(commitments) {
		return errors.New("proof commitment count differs from verification key")
	}
	offsets := []int{0, g1, g1 + g2}
	for i := 0; i <= commitments; i++ {
		offsets = append(offsets, countOffset+4+i*g1)
	}
	for _, offset := range offsets {
		if raw[offset]&0xc0 == 0 {
			return errors.New("uncompressed proof point forbidden")
		}
	}
	return nil
}
