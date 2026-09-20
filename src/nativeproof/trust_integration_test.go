package nativeproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGroth16AuthorizedWallet(t *testing.T) {
	if os.Getenv("LKTRS_PROVE") != "1" {
		t.Skip("set LKTRS_PROVE=1 for real authorized wallet proof and setup loading")
	}
	var loaded *LoadedSetup
	var pin [32]byte
	var err error
	setupDir := os.Getenv("LKTRS_TEST_SETUP")
	if setupDir != "" {
		raw, e := ReadBoundedFile(filepath.Join(setupDir, "manifest.json"), maxManifestBytes)
		if e != nil {
			t.Fatal(e)
		}
		pin = sha256.Sum256(raw)
		// Locally generated test fixture, not an example of authenticating downloads.
		loaded, err = LoadSetup(setupDir, pin)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		params, e := Setup(4)
		if e != nil {
			t.Fatal(e)
		}
		p, v, e := NewBackend()
		if e != nil {
			t.Fatal(e)
		}
		setupDir = filepath.Join(t.TempDir(), "setup")
		pin, e = ExportSetup(setupDir, params, p, v)
		if e != nil {
			t.Fatal(e)
		}
		loaded = &LoadedSetup{Parameters: params, Prover: p, Verifier: v}
	}
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	if err = ExportPublicSetup(setupDir, publicDir, pin); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue := sha256.Sum256([]byte("authorized wallet issue"))
	now := time.Now().Unix()
	policy := TrustPolicy{"lktrs/trust-policy/v1", "integration", hexDigest(pin), base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(pub), 1, hexDigest(issue), 4}
	approval, err := SignSetupApproval(pin, "integration", now-10, now+3600, key)
	if err != nil {
		t.Fatal(err)
	}
	a, x, err := KeyGen(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := KeyGen(x)
	if err != nil {
		t.Fatal(err)
	}
	accounts := []Account{a, b}
	auth := RegistryAuthorization{"lktrs/registry-authorization/v1", "integration", hexDigest(pin), 1, now - 10, now + 3600, hexDigest(issue), 4, nil}
	for i, a := range accounts {
		challenge := sha256.Sum256([]byte{byte(i + 1)})
		enrollment, e := CreateEnrollment(x, a, "alice", string(rune('a'+i)), "integration", pin, pub, challenge)
		if e != nil {
			t.Fatal(e)
		}
		auth.Entries = append(auth.Entries, enrollment)
	}
	registry, err := SignRegistryAuthorization(auth, key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := LoadAuthorizedVerifier(publicDir, policy, approval, now)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewSnapshot(loaded.Parameters, accounts)
	if err != nil {
		t.Fatal(err)
	}
	wrappingKey := make([]byte, 32)
	_, _ = rand.Read(wrappingKey)
	id := sha256.Sum256([]byte("test wallet"))
	vaultPath := filepath.Join(root, "wallet")
	wallet, err := CreateSignerVault(vaultPath, wrappingKey, id, x)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("authenticated registry and persistent wallet")
	sig, err := wallet.Sign(loaded.Prover, ring, 0, issue, 4, msg, 1)
	wallet.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = verifier.Verify(registry, msg, sig, now); err != nil {
		t.Fatal(err)
	}
	if err = verifier.Verify(registry, []byte("tampered"), sig, now); err == nil {
		t.Fatal("wrong message authorized")
	}
	if err = verifier.Verify(registry, msg, sig, now+3600); err == nil {
		t.Fatal("expired approval authorized")
	}
	wallet, err = OpenSignerVault(vaultPath, wrappingKey, id)
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Close()
	if next, e := wallet.NextCounter(issue); e != nil || next != 1 {
		t.Fatal("wallet did not restore counter", e)
	}
	sig2, err := wallet.Sign(loaded.Prover, ring, 1, issue, 4, []byte("after restart"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifier.Verify(registry, []byte("after restart"), sig2, now); err != nil {
		t.Fatal(err)
	}
	if !sig.Statement.Nym.Equal(&sig2.Statement.Nym) || sig.Statement.S.Equal(&sig2.Statement.S) {
		t.Fatal("wallet account switch broke issue scope/counter uniqueness")
	}
	// A deliberately malicious signer bypasses the vault and reuses counter 0.
	reuseMsg := []byte("malicious counter reuse")
	reuseStatement, reuseWitness, e := MakeStatement(loaded.Parameters, accounts, 1, x, b.D, issue, sha256.Sum256(reuseMsg), 3, 4, 0)
	if e != nil {
		t.Fatal(e)
	}
	reused, e := loaded.Prover.Prove(loaded.Parameters, reuseStatement, reuseWitness)
	if e != nil {
		t.Fatal(e)
	}
	traced, e := verifier.Trace(registry, msg, sig, reuseMsg, reused, now)
	if e != nil || traced.Status != TraceTraced || traced.UserID != "alice" {
		t.Fatal("authorized identity tracing", traced, e)
	}
	auth.Epoch = 2
	auth.Entries = auth.Entries[1:]
	revoked, err := SignRegistryAuthorization(auth, key)
	if err != nil {
		t.Fatal(err)
	}
	updated := policy
	updated.RegistryEpoch = 2
	newVerifier, err := LoadAuthorizedVerifier(publicDir, updated, approval, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = newVerifier.Verify(registry, msg, sig, now); err == nil {
		t.Fatal("old registry epoch accepted")
	}
	if err = newVerifier.Verify(revoked, msg, sig, now); err == nil {
		t.Fatal("old proof accepted in changed ring")
	}
	// Verify the actual exported artifacts through the new CLI, if a separately
	// built binary is supplied by the integration invocation.
	if cli := os.Getenv("LKTRS_TEST_CLI"); cli != "" {
		policyRaw, _ := json.Marshal(policy)
		encoded, e := MarshalSigned(sig)
		if e != nil {
			t.Fatal(e)
		}
		for name, data := range map[string][]byte{"policy.json": policyRaw, "approval.json": approval, "registry.json": registry, "message.bin": msg, "signature.bin": encoded} {
			if e = os.WriteFile(filepath.Join(root, name), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		args := []string{"verify-authorized", "--setup", publicDir, "--policy", filepath.Join(root, "policy.json"), "--setup-approval", filepath.Join(root, "approval.json"), "--registry", filepath.Join(root, "registry.json"), "--message", filepath.Join(root, "message.bin"), "--signature", filepath.Join(root, "signature.bin")}
		output, e := exec.Command(cli, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("CLI: %v %s", e, output)
		}
		var result struct {
			Verified bool `json:"verified"`
		}
		if e = json.Unmarshal(output, &result); e != nil || !result.Verified {
			t.Fatalf("CLI result: %s %v", output, e)
		}
		_ = os.WriteFile(filepath.Join(root, "registry.json"), revoked, 0600)
		if output, e = exec.Command(cli, args...).CombinedOutput(); e == nil {
			t.Fatalf("CLI accepted wrong epoch: %s", output)
		}
		t.Log("independent CLI verified the authorized proof and rejected the wrong epoch")
	} else {
		t.Log("independent CLI skipped: LKTRS_TEST_CLI is not set")
	}
	t.Log("real proof: authority setup + registry PoP + independent public load + encrypted wallet restart + authorized trace verified")
}
