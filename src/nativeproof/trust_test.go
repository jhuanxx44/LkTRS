package nativeproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func trustFixture(t *testing.T) (Params, TrustPolicy, ed25519.PrivateKey, RegistryAuthorization, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p, e := Setup(4)
	if e != nil {
		t.Fatal(e)
	}
	pin := sha256.Sum256([]byte("test setup"))
	issue := sha256.Sum256([]byte("test issue"))
	policy := TrustPolicy{"lktrs/trust-policy/v1", "test", hexDigest(pin), base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(pub), 1, hexDigest(issue), 3}
	a, x, e := KeyGen(nil)
	if e != nil {
		t.Fatal(e)
	}
	challenge := sha256.Sum256([]byte("authority issued challenge"))
	enrollment, e := CreateEnrollment(x, a, "alice", "a", "test", pin, pub, challenge)
	if e != nil {
		t.Fatal(e)
	}
	auth := RegistryAuthorization{"lktrs/registry-authorization/v1", "test", hexDigest(pin), 1, 100, 200, hexDigest(issue), 3, []Enrollment{enrollment}}
	raw, e := SignRegistryAuthorization(auth, key)
	if e != nil {
		t.Fatal(e)
	}
	return p, policy, key, auth, raw
}
func TestEnrollmentProofOfPossession(t *testing.T) {
	_, policy, key, auth, _ := trustFixture(t)
	pin, _ := ParseDigest(policy.ManifestSHA256)
	pub := key.Public().(ed25519.PublicKey)
	original := auth.Entries[0]
	challenge, _ := ParseDigest(original.Challenge)
	reg, e := VerifyEnrollment(original, "test", pin, pub, challenge)
	if e != nil || reg.UserID != "alice" {
		t.Fatal("valid enrollment", e)
	}
	tests := map[string]func(*Enrollment){
		"identity": func(e *Enrollment) { e.UserID = "mallory" }, "account": func(e *Enrollment) { e.AccountID = "b" },
		"response": func(e *Enrollment) { e.Response = scalarHex(big.NewInt(7)) }, "commitment": func(e *Enrollment) { e.Commitment = e.Y },
		"D": func(e *Enrollment) { e.D = scalarHex(big.NewInt(1)) }, "missing proof": func(e *Enrollment) { e.Response = "" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			bad := original
			change(&bad)
			if _, e := VerifyEnrollment(bad, "test", pin, pub, challenge); e == nil {
				t.Fatal("altered enrollment accepted")
			}
		})
	}
	if _, e = VerifyEnrollment(original, "other", pin, pub, challenge); e == nil {
		t.Fatal("namespace substitution")
	}
	other := sha256.Sum256([]byte("other"))
	if _, e = VerifyEnrollment(original, "test", other, pub, challenge); e == nil {
		t.Fatal("setup substitution")
	}
	if _, e = VerifyEnrollment(original, "test", pin, pub, other); e == nil {
		t.Fatal("challenge substitution")
	}
	otherKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e = VerifyEnrollment(original, "test", pin, otherKey, challenge); e == nil {
		t.Fatal("authority substitution")
	}
	// The old consistency-only registry admits a copied public account under a
	// different user label. Binding that label into PoP prevents this relabeling.
	if _, e = NewRegistry([]Registration{{"mallory", reg.Account}}); e != nil {
		t.Fatal("counterexample fixture", e)
	}
}
func TestAuthorityProvisioning(t *testing.T) {
	p, policy, key, auth, raw := trustFixture(t)
	if _, _, e := authorizedContext(p, policy, raw, 150); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*TrustPolicy){
		"namespace": func(p *TrustPolicy) { p.Namespace = "other" }, "epoch": func(p *TrustPolicy) { p.RegistryEpoch++ },
		"quota": func(p *TrustPolicy) { p.K++ }, "issue": func(p *TrustPolicy) { p.Issue = hexDigest(sha256.Sum256([]byte("other issue"))) },
		"setup": func(p *TrustPolicy) { p.ManifestSHA256 = hexDigest(sha256.Sum256([]byte("other setup"))) },
		"key": func(p *TrustPolicy) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			p.RegistryAuthority = base64.StdEncoding.EncodeToString(pub)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := policy
			change(&bad)
			if _, _, e := authorizedContext(p, bad, raw, 150); e == nil {
				t.Fatal("wrong trust policy accepted")
			}
		})
	}
	for _, now := range []int64{99, 200, 201} {
		if _, _, e := authorizedContext(p, policy, raw, now); e == nil {
			t.Fatal("expired/not-yet-valid registry accepted")
		}
	}
	var env authorityEnvelope
	_ = json.Unmarshal(raw, &env)
	corruptedSignature, _ := decodeB64(env.Signature)
	corruptedSignature[0] ^= 1
	badEnvelope := env
	badEnvelope.Signature = base64.StdEncoding.EncodeToString(corruptedSignature)
	badSignatureDocument, _ := json.Marshal(badEnvelope)
	if _, _, e := authorizedContext(p, policy, badSignatureDocument, 150); e == nil {
		t.Fatal("invalid signature over unchanged registry accepted")
	}
	payload, _ := decodeB64(env.Payload)
	var document RegistryAuthorization
	_ = json.Unmarshal(payload, &document)
	document.K++
	payload, _ = json.Marshal(document)
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	bad, _ := json.Marshal(env)
	if _, _, e := authorizedContext(p, policy, bad, 150); e == nil {
		t.Fatal("tampered authority document accepted")
	}
	bad = append([]byte(`{"payload_b64":"bogus",`), raw[1:]...)
	if _, _, e := authorizedContext(p, policy, bad, 150); e == nil {
		t.Fatal("duplicate JSON accepted")
	}
	// A valid authority signature cannot bypass invalid ownership proofs.
	auth.Entries[0].UserID = "mallory"
	bad, e := authoritySign(auth, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = authorizedContext(p, policy, bad, 150); e == nil {
		t.Fatal("signed invalid proof accepted")
	}
	pin, _ := ParseDigest(policy.ManifestSHA256)
	approval, e := SignSetupApproval(pin, "test", 100, 200, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifySetupApproval(policy, approval, 150); e != nil {
		t.Fatal(e)
	}
	if e = verifySetupApproval(policy, approval, 200); e == nil {
		t.Fatal("expired setup approval accepted")
	}
	if _, _, e = authorizedContext(p, policy, approval, 150); e == nil {
		t.Fatal("setup approval reused as registry")
	}
	if e = verifySetupApproval(policy, raw, 150); e == nil {
		t.Fatal("registry reused as setup approval")
	}
	if _, e = LoadAuthorizedVerifier(t.TempDir(), policy, raw, 150); e == nil {
		t.Fatal("invalid approval allowed artifact load")
	}
}
func TestAuthorityRegistryConsistencyAndRevocation(t *testing.T) {
	p, policy, key, auth, raw := trustFixture(t)
	pub := key.Public().(ed25519.PublicKey)
	pin, _ := ParseDigest(policy.ManifestSHA256)
	_, originalRegistry, e := authorizedContext(p, policy, raw, 150)
	if e != nil {
		t.Fatal(e)
	}
	account, x, e := KeyGen(nil)
	if e != nil {
		t.Fatal(e)
	}
	challenge := sha256.Sum256([]byte("bob nonce"))
	b, e := CreateEnrollment(x, account, "bob", "b", "test", pin, pub, challenge)
	if e != nil {
		t.Fatal(e)
	}
	auth.Entries = append(auth.Entries, b)
	signed, e := SignRegistryAuthorization(auth, key)
	if e != nil {
		t.Fatal(e)
	}
	ctx, registry, e := authorizedContext(p, policy, signed, 150)
	if e != nil {
		t.Fatal(e)
	}
	if len(ctx.accounts) != 2 || len(registry.entries) != 2 || len(originalRegistry.entries) != 1 {
		t.Fatal("registry ownership")
	}
	for _, a := range ctx.accounts {
		if a.D != nil {
			t.Fatal("public context unexpectedly includes registration exponent")
		}
	}
	bad := auth
	bad.Entries = append([]Enrollment{}, auth.Entries...)
	bad.Entries = append(bad.Entries, b)
	if _, e = SignRegistryAuthorization(bad, key); e == nil {
		t.Fatal("duplicate registration accepted")
	}
	bad.Entries = []Enrollment{auth.Entries[0], b}
	bad.Entries[1], e = CreateEnrollment(x, account, "alice", "b", "test", pin, pub, challenge)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = SignRegistryAuthorization(bad, key); e == nil {
		t.Fatal("one user with two trace keys accepted")
	}
	// Revocation changes the active signed snapshot and externally pinned epoch.
	auth.Epoch = 2
	auth.Entries = []Enrollment{b}
	newRaw, e := SignRegistryAuthorization(auth, key)
	if e != nil {
		t.Fatal(e)
	}
	policy.RegistryEpoch = 2
	if _, _, e = authorizedContext(p, policy, signed, 150); e == nil {
		t.Fatal("old epoch rollback accepted")
	}
	current, _, e := authorizedContext(p, policy, newRaw, 150)
	if e != nil || len(current.accounts) != 1 {
		t.Fatal("revoked current snapshot", e)
	}
}

func TestSetupApprovalExpiryRechecked(t *testing.T) {
	_, policy, key, _, registry := trustFixture(t)
	pin, _ := ParseDigest(policy.ManifestSHA256)
	approval, e := SignSetupApproval(pin, "test", 100, 120, key)
	if e != nil {
		t.Fatal(e)
	}
	// Deliberately no proof backend: an expired setup must be rejected before
	// touching the otherwise still-valid registry or proof verifier.
	verifier := &AuthorizedVerifier{loaded: &LoadedSetup{}, policy: policy, approval: approval}
	if e = verifier.Verify(registry, nil, Signed{}, 150); e == nil || e.Error() != "setup approval scope or validity mismatch" {
		t.Fatal("setup expiry was not checked first", e)
	}
	if _, e = verifier.Trace(registry, nil, Signed{}, nil, Signed{}, 150); e == nil || e.Error() != "setup approval scope or validity mismatch" {
		t.Fatal("trace did not recheck setup expiry", e)
	}
}

func TestTrustFieldDecodersBoundAllocation(t *testing.T) {
	oversized := strings.Repeat("0", 2<<20)
	for name, decode := range map[string]func() error{
		"point":     func() error { _, e := trustPoint(oversized); return e },
		"scalar":    func() error { _, e := trustScalar(oversized, true); return e },
		"authority": func() error { _, e := authorityKey(oversized); return e },
	} {
		t.Run(name, func(t *testing.T) {
			if e := decode(); e == nil {
				t.Fatal("oversized field accepted")
			}
			measured := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = decode()
				}
			})
			if measured.AllocedBytesPerOp() > 1024 {
				t.Fatalf("oversized field allocated %d bytes before rejection", measured.AllocedBytesPerOp())
			}
		})
	}
}
