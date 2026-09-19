package nativeproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/backend/groth16"
	bngroth "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"os"
	"path/filepath"
	"testing"
)

func TestSetupParameterEncoding(t *testing.T) {
	p, err := Setup(3)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalParams(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := UnmarshalParams(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalParams(q)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("noncanonical parameter round trip", err)
	}
	for _, bad := range [][]byte{raw[:10], raw[:len(raw)-1], append(append([]byte{}, raw...), 0)} {
		if _, err := UnmarshalParams(bad); err == nil {
			t.Fatal("malformed parameters accepted")
		}
	}
	bad := append([]byte{}, raw...)
	binary.BigEndian.PutUint32(bad[8:12], 0xffffffff)
	if _, err := UnmarshalParams(bad); err == nil {
		t.Fatal("hostile power count accepted")
	}
	bad = append([]byte{}, raw...)
	copy(bad[len(bad)-32:], raw[len(raw)-64:len(raw)-32])
	if _, err := UnmarshalParams(bad); err == nil {
		t.Fatal("inconsistent powers accepted")
	}
}

func TestPinnedSetupArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vk.bin")
	raw := []byte("test artifact")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ref := ArtifactDigest{Size: int64(len(raw)), SHA256: hexDigest(sha256.Sum256(raw))}
	got, err := readArtifact(dir, "vk.bin", ref, 100)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("honest artifact rejected", err)
	}
	if err := os.WriteFile(path, []byte("bad artifact!"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readArtifact(dir, "vk.bin", ref, 100); err == nil {
		t.Fatal("changed artifact accepted")
	}
	if _, err = readArtifact(dir, "vk.bin", ref, 2); err == nil {
		t.Fatal("oversized artifact accepted")
	}
}

// Tiny circuits exercise the serialization boundary only, not Lk-TRS security.
type setupEncodingCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *setupEncodingCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func TestProvingKeyPreflight(t *testing.T) {
	cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &setupEncodingCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	pk, _, e := groth16.Setup(cs)
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	if _, e = pk.WriteTo(&b); e != nil {
		t.Fatal(e)
	}
	raw := b.Bytes()
	if e = preflightProvingKey(raw, cs); e != nil {
		t.Fatal("honest PK layout rejected", e)
	}
	tests := map[string]func([]byte) []byte{
		"domain":      func(b []byte) []byte { binary.BigEndian.PutUint64(b[:8], 1<<62); return b },
		"point count": func(b []byte) []byte { binary.BigEndian.PutUint32(b[8+5*32+1+3*32:], 0xffffffff); return b },
		"raw marker":  func(b []byte) []byte { b[8+5*32+1] &= 0x3f; return b },
		"truncation":  func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":    func(b []byte) []byte { return append(b, 0) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if e := preflightProvingKey(mutate(append([]byte{}, raw...)), cs); e == nil {
				t.Fatal("malformed PK accepted")
			}
		})
	}
}

func TestPublicContextRoundtrip(t *testing.T) {
	p, accounts, st, _ := fixture(t)
	ctx, e := NewVerificationContext(p, accounts, st.Issue, st.K)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := MarshalVerificationContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := UnmarshalVerificationContext(p, raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = restored.check([]byte("message one"), st); e != nil {
		t.Fatal(e)
	}
	for _, a := range restored.accounts {
		if a.D != nil {
			t.Fatal("account exponent leaked into verification context")
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte("{}")...), bytes.Replace(raw, []byte(`"k": 3`), []byte(`"k": 0`), 1), bytes.Replace(raw, []byte(`"k": 3`), []byte(`"k": 3, "k": 4`), 1)} {
		if _, e = UnmarshalVerificationContext(p, bad); e == nil {
			t.Fatal("invalid context accepted")
		}
	}
}

func TestSetupManifestPinsAndSchema(t *testing.T) {
	dir := t.TempDir()
	digest := hexDigest(sha256.Sum256([]byte("artifact")))
	m := SetupManifest{Format: setupFormat, Profile: CircuitVersion, SetupKind: "local-single-party", PairingCurve: "bn254", StandaloneCurve: "secp256k1", PairingScalarOrder: bnfr.Modulus().String(), StandaloneScalarOrder: secfr.Modulus().String(), Gnark: gnarkVersion, GnarkCrypto: cryptoVersion, Capacity: 3, Circuit: CircuitDescriptor{SHA256: digest}, Parameters: ArtifactDigest{digest, 10}, ProvingKey: ArtifactDigest{digest, 10}, VerifyingKey: ArtifactDigest{digest, 10}}
	write := func(raw []byte) [32]byte {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		return sha256.Sum256(raw)
	}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	pin := write(raw)
	if _, _, e = readManifest(dir, pin); e != nil {
		t.Fatal(e)
	}
	if _, _, e = readManifest(dir, [32]byte{}); e == nil {
		t.Fatal("unpinned manifest accepted")
	}
	changed := append([]byte{}, raw...)
	changed = append(changed, ' ')
	write(changed)
	if _, _, e = readManifest(dir, pin); e == nil {
		t.Fatal("changed manifest accepted under old pin")
	}
	for name, mutate := range map[string]func(*SetupManifest){
		"version": func(m *SetupManifest) { m.Format = "v0" }, "curve": func(m *SetupManifest) { m.PairingCurve = "bls12-381" }, "library": func(m *SetupManifest) { m.Gnark = "v0" }, "ceremony": func(m *SetupManifest) { m.SetupKind = "mpc" }, "length": func(m *SetupManifest) { m.ProvingKey.Size = 1 << 62 }, "capacity": func(m *SetupManifest) { m.Capacity = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := m
			mutate(&copy)
			b, _ := json.Marshal(copy)
			pin := write(b)
			if _, _, e := readManifest(dir, pin); e == nil {
				t.Fatal("unsupported setup metadata accepted")
			}
		})
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"capacity":3`), []byte(`"capacity":3,"capacity":4`), 1), append(append([]byte{}, raw...), []byte("{}")...)} {
		pin := write(bad)
		if _, _, e := readManifest(dir, pin); e == nil {
			t.Fatal("ambiguous manifest accepted")
		}
	}
}

func TestBundleDoesNotOverwriteAndCleansFailure(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "bundle")
	if e := newBundle(dir, func(p string) error { return os.WriteFile(filepath.Join(p, "sentinel"), []byte("keep"), 0600) }); e != nil {
		t.Fatal(e)
	}
	if e := newBundle(dir, func(string) error { return nil }); e == nil {
		t.Fatal("existing bundle overwritten")
	}
	broken := filepath.Join(root, "broken")
	if e := newBundle(broken, func(string) error { return errors.New("injected write failure") }); e == nil {
		t.Fatal("write failure masked")
	}
	if _, e := os.Stat(broken); !os.IsNotExist(e) {
		t.Fatal("partial bundle published")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 1 {
		t.Fatal("staging directory leaked", e)
	}
}

func TestSetupLibraryVersions(t *testing.T) {
	raw, e := os.ReadFile("go.mod")
	if e != nil {
		t.Fatal(e)
	}
	for module, version := range map[string]string{"github.com/consensys/gnark": gnarkVersion, "github.com/consensys/gnark-crypto": cryptoVersion} {
		if !bytes.Contains(raw, []byte(module+" "+version+"\n")) {
			t.Fatal("setup codec version drift", module)
		}
	}
}

func TestVerifierCircuitLayout(t *testing.T) {
	cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &setupEncodingCircuit{})
	if e != nil {
		t.Fatal(e)
	}
	_, vk, e := groth16.Setup(cs)
	if e != nil {
		t.Fatal(e)
	}
	ch, e := digestWriter(cs)
	if e != nil {
		t.Fatal(e)
	}
	serialize := func() ([]byte, [32]byte) {
		t.Helper()
		var b bytes.Buffer
		if _, e := vk.WriteTo(&b); e != nil {
			t.Fatal(e)
		}
		return b.Bytes(), sha256.Sum256(b.Bytes())
	}
	raw, kid := serialize()
	if _, e := loadVerifierForCircuit(raw, ch, kid, cs); e != nil {
		t.Fatal("honest key rejected", e)
	}
	bad := ch
	bad[0] ^= 1
	if _, e := loadVerifierForCircuit(raw, bad, kid, cs); e == nil {
		t.Fatal("wrong R1CS digest accepted")
	}
	native := vk.(*bngroth.VerifyingKey)
	native.G1.K = append(native.G1.K, native.G1.Alpha)
	raw, kid = serialize()
	if _, e := loadVerifierForCircuit(raw, ch, kid, cs); e == nil {
		t.Fatal("wrong public wire layout accepted")
	}
	native.G1.K = native.G1.K[:len(native.G1.K)-1]
	native.PublicAndCommitmentCommitted = [][]int{{1}}
	raw, kid = serialize()
	if _, e := loadVerifierForCircuit(raw, ch, kid, cs); e == nil {
		t.Fatal("wrong commitment metadata accepted")
	}
}
