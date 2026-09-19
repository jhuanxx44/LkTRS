package nativeproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/backend/groth16"
	bngroth "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
)

const (
	setupFormat        = "lktrs/setup/v1"
	gnarkVersion       = "v0.16.3"
	cryptoVersion      = "v0.21.0"
	maxManifestBytes   = 1 << 20
	maxProvingKeyBytes = 1 << 30
)

type ArtifactDigest struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"bytes"`
}

type CircuitDescriptor struct {
	SHA256            string `json:"sha256"`
	Constraints       int    `json:"constraints"`
	PublicVariables   int    `json:"public_variables_including_constant"`
	SecretVariables   int    `json:"secret_variables"`
	InternalVariables int    `json:"internal_variables"`
	Commitments       int    `json:"commitments"`
}

// SetupManifest describes public setup artifacts, not an MPC attestation.
// Its digest must be provisioned independently of a candidate proof or bundle.
// The proving key is public proof-generation material, not a user signing key.
type SetupManifest struct {
	Format                string            `json:"format"`
	Profile               string            `json:"profile"`
	SetupKind             string            `json:"setup_kind"`
	PairingCurve          string            `json:"pairing_curve"`
	StandaloneCurve       string            `json:"standalone_curve"`
	PairingScalarOrder    string            `json:"pairing_scalar_order"`
	StandaloneScalarOrder string            `json:"standalone_scalar_order"`
	Gnark                 string            `json:"gnark"`
	GnarkCrypto           string            `json:"gnark_crypto"`
	Circuit               CircuitDescriptor `json:"circuit"`
	Capacity              int               `json:"capacity"`
	Parameters            ArtifactDigest    `json:"parameters"`
	ProvingKey            ArtifactDigest    `json:"proving_key"`
	VerifyingKey          ArtifactDigest    `json:"verifying_key"`
}

type LoadedSetup struct {
	Parameters Params
	Prover     *Prover // nil for LoadPublicSetup
	Verifier   *Verifier
	Manifest   SetupManifest
}

func hexDigest(h [32]byte) string { return hex.EncodeToString(h[:]) }
func ParseDigest(text string) ([32]byte, error) {
	var out [32]byte
	b, e := hex.DecodeString(text)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != text {
		return out, errors.New("digest must be 32 bytes in lowercase hex")
	}
	copy(out[:], b)
	return out, nil
}
func strictJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8 JSON")
	}
	if e := rejectDuplicateJSON(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var trailing any
	if e := d.Decode(&trailing); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func describeCircuit(cs constraint.ConstraintSystem) (CircuitDescriptor, error) {
	hash, e := digestWriter(cs)
	if e != nil {
		return CircuitDescriptor{}, e
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return CircuitDescriptor{}, errors.New("unsupported circuit commitments")
	}
	return CircuitDescriptor{hexDigest(hash), cs.GetNbConstraints(), cs.GetNbPublicVariables(), cs.GetNbSecretVariables(), cs.GetNbInternalVariables(), len(commitments)}, nil
}

// ReadBoundedFile limits allocation before reading caller-selected files.
func ReadBoundedFile(path string, max int64) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("artifact must be a regular file, not a symlink or device")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !os.SameFile(before, stat) || !stat.Mode().IsRegular() || stat.Size() < 0 || stat.Size() > max {
		return nil, errors.New("invalid or oversized artifact")
	}
	// Allocate once for large compressed proving keys; ReadAll's growing
	// buffers otherwise multiply the peak memory needed during a reload.
	b := make([]byte, int(stat.Size()))
	if _, e := io.ReadFull(f, b); e != nil {
		return nil, e
	}
	var extra [1]byte
	if n, e := f.Read(extra[:]); n != 0 || e != io.EOF {
		return nil, errors.New("artifact changed while reading")
	}
	return b, nil
}
func readArtifact(dir, name string, ref ArtifactDigest, max int64) ([]byte, error) {
	if ref.Size < 1 || ref.Size > max {
		return nil, fmt.Errorf("invalid %s size", name)
	}
	digest, e := ParseDigest(ref.SHA256)
	if e != nil {
		return nil, e
	}
	raw, e := ReadBoundedFile(filepath.Join(dir, name), ref.Size)
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != ref.Size || sha256.Sum256(raw) != digest {
		return nil, fmt.Errorf("%s digest or size mismatch", name)
	}
	return raw, nil
}
func writeArtifact(dir, name string, w io.WriterTo, max int64) (ArtifactDigest, error) {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ArtifactDigest{}, e
	}
	defer f.Close()
	h := sha256.New()
	bw := &budgetWriter{w: io.MultiWriter(f, h), left: max}
	if _, e = w.WriteTo(bw); e != nil {
		return ArtifactDigest{}, e
	}
	if e = f.Sync(); e != nil {
		return ArtifactDigest{}, e
	}
	return ArtifactDigest{hex.EncodeToString(h.Sum(nil)), max - bw.left}, nil
}

type budgetWriter struct {
	w    io.Writer
	left int64
}

func (w *budgetWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.left {
		return 0, errors.New("artifact exceeds size budget")
	}
	n, e := w.w.Write(b)
	w.left -= int64(n)
	return n, e
}
func newBundle(dir string, fill func(string) error) error {
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		return errors.New("output bundle already exists or cannot be inspected")
	}
	parent := filepath.Dir(dir)
	if e := os.MkdirAll(parent, 0700); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(parent, ".lktrs-export-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = fill(tmp); e != nil {
		return e
	}
	d, e := os.Open(tmp)
	if e != nil {
		return e
	}
	e = d.Sync()
	_ = d.Close()
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, dir); e != nil {
		return e
	}
	d, e = os.Open(parent)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// ExportSetup writes immutable portable parameters and compressed PK/VK files.
// It refuses an existing destination. No user secrets or setup trapdoors are
// serialized. Exporting is not evidence of honest setup or secret erasure.
func ExportSetup(dir string, params Params, p *Prover, v *Verifier) ([32]byte, error) {
	var pin [32]byte
	if p == nil || v == nil || p.pk == nil || p.cs == nil || v.vk == nil {
		return pin, errors.New("missing setup")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.circuitHash != v.circuitHash || p.keyID != v.keyID {
		return pin, errors.New("prover/verifier identity mismatch")
	}
	pp, e := MarshalParams(params)
	if e != nil {
		return pin, e
	}
	descriptor, e := describeCircuit(p.cs)
	if e != nil {
		return pin, e
	}
	if descriptor.SHA256 != hexDigest(p.circuitHash) {
		return pin, errors.New("prover circuit identity mismatch")
	}
	m := SetupManifest{Format: setupFormat, Profile: CircuitVersion, SetupKind: "local-single-party", PairingCurve: "bn254", StandaloneCurve: "secp256k1", PairingScalarOrder: fr.Modulus().String(), StandaloneScalarOrder: secfr.Modulus().String(), Gnark: gnarkVersion, GnarkCrypto: cryptoVersion, Circuit: descriptor, Capacity: len(params.Powers) - 1}
	e = newBundle(dir, func(tmp string) error {
		var err error
		m.Parameters, err = writeArtifact(tmp, "parameters.bin", bytes.NewReader(pp), maxParamsBytes)
		if err != nil {
			return err
		}
		m.VerifyingKey, err = writeArtifact(tmp, "vk.bin", v.vk, maxProofBytes)
		if err != nil {
			return err
		}
		if m.VerifyingKey.SHA256 != hexDigest(p.keyID) {
			return errors.New("VK identity mismatch")
		}
		m.ProvingKey, err = writeArtifact(tmp, "pk.bin", p.pk, maxProvingKeyBytes)
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		pin = sha256.Sum256(raw)
		_, err = writeArtifact(tmp, "manifest.json", bytes.NewReader(raw), maxManifestBytes)
		return err
	})
	return pin, e
}
func readManifest(dir string, pin [32]byte) (SetupManifest, []byte, error) {
	var m SetupManifest
	if pin == ([32]byte{}) {
		return m, nil, errors.New("trusted manifest digest required")
	}
	raw, e := ReadBoundedFile(filepath.Join(dir, "manifest.json"), maxManifestBytes)
	if e != nil {
		return m, nil, e
	}
	if sha256.Sum256(raw) != pin {
		return m, nil, errors.New("manifest digest mismatch")
	}
	if e = strictJSON(raw, &m); e != nil {
		return m, nil, e
	}
	if m.Format != setupFormat || m.Profile != CircuitVersion || m.SetupKind != "local-single-party" || m.PairingCurve != "bn254" || m.StandaloneCurve != "secp256k1" || m.PairingScalarOrder != fr.Modulus().String() || m.StandaloneScalarOrder != secfr.Modulus().String() || m.Gnark != gnarkVersion || m.GnarkCrypto != cryptoVersion || m.Capacity < 1 || m.Capacity > 1<<16 {
		return m, nil, errors.New("unsupported setup manifest profile")
	}
	for _, ref := range []ArtifactDigest{m.Parameters, m.ProvingKey, m.VerifyingKey} {
		if _, e = ParseDigest(ref.SHA256); e != nil || ref.Size <= 0 {
			return m, nil, errors.New("invalid manifest artifact")
		}
	}
	if m.Parameters.Size > maxParamsBytes || m.ProvingKey.Size > maxProvingKeyBytes || m.VerifyingKey.Size > maxProofBytes {
		return m, nil, errors.New("manifest artifact exceeds size budget")
	}
	if _, e = ParseDigest(m.Circuit.SHA256); e != nil {
		return m, nil, e
	}
	return m, raw, nil
}

func LoadPublicSetup(dir string, pin [32]byte) (*LoadedSetup, error) {
	return loadSetup(dir, pin, false)
}
func LoadSetup(dir string, pin [32]byte) (*LoadedSetup, error) { return loadSetup(dir, pin, true) }
func loadSetup(dir string, pin [32]byte, withProver bool) (*LoadedSetup, error) {
	m, _, e := readManifest(dir, pin)
	if e != nil {
		return nil, e
	}
	raw, e := readArtifact(dir, "parameters.bin", m.Parameters, maxParamsBytes)
	if e != nil {
		return nil, e
	}
	params, e := UnmarshalParams(raw)
	if e != nil {
		return nil, e
	}
	if len(params.Powers)-1 != m.Capacity {
		return nil, errors.New("parameter capacity mismatch")
	}
	key, e := readArtifact(dir, "vk.bin", m.VerifyingKey, maxProofBytes)
	if e != nil {
		return nil, e
	}
	if e = preflightVerifyingKey(key); e != nil {
		return nil, e
	}
	cs, e := Compile()
	if e != nil {
		return nil, e
	}
	descriptor, e := describeCircuit(cs)
	if e != nil {
		return nil, e
	}
	if descriptor != m.Circuit {
		return nil, errors.New("manifest circuit differs from locally compiled circuit")
	}
	ch, _ := ParseDigest(m.Circuit.SHA256)
	kid, _ := ParseDigest(m.VerifyingKey.SHA256)
	verifier, e := loadVerifierForCircuit(key, ch, kid, cs)
	if e != nil {
		return nil, e
	}
	result := &LoadedSetup{Parameters: params, Verifier: verifier, Manifest: m}
	if !withProver {
		return result, nil
	}
	raw, e = readArtifact(dir, "pk.bin", m.ProvingKey, maxProvingKeyBytes)
	if e != nil {
		return nil, e
	}
	if e = preflightProvingKey(raw, cs); e != nil {
		return nil, fmt.Errorf("PK layout: %w", e)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	r := bytes.NewReader(raw)
	if _, e = pk.ReadFrom(r); e != nil {
		return nil, e
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing PK bytes")
	}
	np, nv := pk.(*bngroth.ProvingKey), verifier.vk.(*bngroth.VerifyingKey)
	if !np.G1.Alpha.Equal(&nv.G1.Alpha) || !np.G1.Beta.Equal(&nv.G1.Beta) || !np.G1.Delta.Equal(&nv.G1.Delta) || !np.G2.Beta.Equal(&nv.G2.Beta) || !np.G2.Delta.Equal(&nv.G2.Delta) {
		return nil, errors.New("PK/VK setup points differ")
	}
	result.Prover = &Prover{cs: cs, pk: pk, circuitHash: ch, keyID: kid}
	return result, nil
}

// ExportPublicSetup produces a directory that LoadPublicSetup can use with the
// same externally provisioned pin, without copying the (large) proving key.
func ExportPublicSetup(src, dst string, pin [32]byte) error {
	if _, e := LoadPublicSetup(src, pin); e != nil {
		return e
	}
	m, manifest, e := readManifest(src, pin)
	if e != nil {
		return e
	}
	pp, e := readArtifact(src, "parameters.bin", m.Parameters, maxParamsBytes)
	if e != nil {
		return e
	}
	vk, e := readArtifact(src, "vk.bin", m.VerifyingKey, maxProofBytes)
	if e != nil {
		return e
	}
	return newBundle(dst, func(tmp string) error {
		for _, f := range []struct {
			name string
			data []byte
		}{{"manifest.json", manifest}, {"parameters.bin", pp}, {"vk.bin", vk}} {
			if _, err := writeArtifact(tmp, f.name, bytes.NewReader(f.data), int64(len(f.data))); err != nil {
				return err
			}
		}
		return nil
	})
}
