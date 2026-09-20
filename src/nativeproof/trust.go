package nativeproof

// Authority signatures authenticate provisioning decisions. They neither prove
// an honest setup ceremony nor turn an asserted user label into a civil identity.
import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

const trustDomain = "lktrs/authority-signature/v1\x00"
const maxTrustBytes = 16 << 20

// TrustPolicy is an independently provisioned application input, never a field
// accepted from a candidate signature. Epoch is exact: freshness across restart
// requires the application to retain/update this trusted policy without rollback.
type TrustPolicy struct {
	Format            string `json:"format"`
	Namespace         string `json:"namespace"`
	ManifestSHA256    string `json:"manifest_sha256"`
	SetupAuthority    string `json:"setup_authority"`
	RegistryAuthority string `json:"registry_authority"`
	RegistryEpoch     uint64 `json:"registry_epoch"`
	Issue             string `json:"issue"`
	K                 uint32 `json:"k"`
}

type authorityEnvelope struct {
	Payload   string `json:"payload_b64"`
	Signature string `json:"signature_b64"`
}
type setupApproval struct {
	Format         string `json:"format"`
	Namespace      string `json:"namespace"`
	ManifestSHA256 string `json:"manifest_sha256"`
	NotBefore      int64  `json:"not_before"`
	NotAfter       int64  `json:"not_after"`
}

func validTrustID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@/-", c) {
			return false
		}
	}
	return true
}
func authorityKey(encoded string) (ed25519.PublicKey, error) {
	if len(encoded) != base64.StdEncoding.EncodedLen(ed25519.PublicKeySize) {
		return nil, errors.New("invalid authority key length")
	}
	b, e := decodeB64(encoded)
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("authority must be an independently trusted Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}
func (p TrustPolicy) validate() error {
	if p.Format != "lktrs/trust-policy/v1" || !validTrustID(p.Namespace) || p.RegistryEpoch == 0 || p.K == 0 {
		return errors.New("invalid trust policy")
	}
	h, e := ParseDigest(p.ManifestSHA256)
	if e != nil || h == ([32]byte{}) {
		return errors.New("invalid setup identity")
	}
	if _, e = decodeIssue(p.Issue); e != nil {
		return e
	}
	if _, e = authorityKey(p.SetupAuthority); e != nil {
		return e
	}
	_, e = authorityKey(p.RegistryAuthority)
	return e
}
func ParseTrustPolicy(raw []byte) (TrustPolicy, error) {
	var p TrustPolicy
	if len(raw) > 8192 {
		return p, errors.New("oversized trust policy")
	}
	if e := strictJSON(raw, &p); e != nil {
		return p, e
	}
	return p, p.validate()
}
func authoritySign(document any, signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("missing authority signer")
	}
	key, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(key) != 32 {
		return nil, errors.New("authority signer must use Ed25519")
	}
	raw, e := json.Marshal(document)
	if e != nil {
		return nil, e
	}
	if len(raw) > maxTrustBytes/2 {
		return nil, errors.New("oversized authority document")
	}
	message := append([]byte(trustDomain), raw...)
	sig, e := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if e != nil {
		return nil, e
	}
	if !ed25519.Verify(key, message, sig) {
		return nil, errors.New("authority signer returned invalid signature")
	}
	return json.Marshal(authorityEnvelope{base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(sig)})
}
func authorityVerify(raw []byte, key ed25519.PublicKey, out any) error {
	if len(raw) > maxTrustBytes || len(key) != 32 {
		return errors.New("invalid authority envelope or key")
	}
	var env authorityEnvelope
	if e := strictJSON(raw, &env); e != nil {
		return e
	}
	payload, e := decodeB64(env.Payload)
	if e != nil {
		return e
	}
	sig, e := decodeB64(env.Signature)
	if e != nil {
		return e
	}
	if !ed25519.Verify(key, append([]byte(trustDomain), payload...), sig) {
		return errors.New("invalid authority signature")
	}
	return strictJSON(payload, out)
}
func validTrustTime(before, after, now int64) bool {
	return before >= 0 && after > before && now >= before && now < after
}

// SignSetupApproval is an explicit endorsement of exact manifest bytes by hash.
// The caller must review setup provenance before signing; crypto.Signer permits
// an external key service without an authority private key in this package.
func SignSetupApproval(pin [32]byte, namespace string, before, after int64, signer crypto.Signer) ([]byte, error) {
	if pin == ([32]byte{}) || !validTrustID(namespace) || !validTrustTime(before, after, before) {
		return nil, errors.New("invalid setup approval")
	}
	return authoritySign(setupApproval{"lktrs/setup-approval/v1", namespace, hexDigest(pin), before, after}, signer)
}
func verifySetupApproval(policy TrustPolicy, raw []byte, now int64) error {
	if e := policy.validate(); e != nil {
		return e
	}
	key, _ := authorityKey(policy.SetupAuthority)
	var a setupApproval
	if e := authorityVerify(raw, key, &a); e != nil {
		return e
	}
	if a.Format != "lktrs/setup-approval/v1" || a.Namespace != policy.Namespace || a.ManifestSHA256 != policy.ManifestSHA256 || !validTrustTime(a.NotBefore, a.NotAfter, now) {
		return errors.New("setup approval scope or validity mismatch")
	}
	return nil
}

// Enrollment is a Schnorr proof of the secret x for this exact authority,
// namespace, setup, user, account, and enrollment challenge. D is public here.
// The authority must authenticate UserID and issue/check Challenge externally.
type Enrollment struct {
	UserID     string `json:"user_id"`
	AccountID  string `json:"account_id"`
	U          string `json:"u"`
	Y          string `json:"y"`
	D          string `json:"d"`
	Challenge  string `json:"challenge"`
	Commitment string `json:"commitment"`
	Response   string `json:"response"`
}

func trustPoint(encoded string) (secp256k1.G1Affine, error) {
	if len(encoded) != 128 {
		return secp256k1.G1Affine{}, errors.New("invalid enrollment point length")
	}
	b, e := hex.DecodeString(encoded)
	if e != nil || len(b) != 64 || hex.EncodeToString(b) != encoded {
		return secp256k1.G1Affine{}, errors.New("noncanonical enrollment point")
	}
	return readSecp(bytes.NewReader(b))
}
func trustScalar(encoded string, nonzero bool) (*big.Int, error) {
	if len(encoded) != 64 {
		return nil, errors.New("invalid enrollment scalar length")
	}
	b, e := hex.DecodeString(encoded)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != encoded {
		return nil, errors.New("noncanonical enrollment scalar")
	}
	n := new(big.Int).SetBytes(b)
	if n.Cmp(secfr.Modulus()) >= 0 || (nonzero && n.Sign() == 0) {
		return nil, errors.New("invalid enrollment scalar")
	}
	return n, nil
}
func scalarHex(n *big.Int) string { return hex.EncodeToString(n.FillBytes(make([]byte, 32))) }
func enrollmentChallenge(e Enrollment, namespace string, pin [32]byte, key ed25519.PublicKey) (*big.Int, error) {
	// JSON of a fixed struct is unambiguous; the response is not part of the
	// challenge. Including the commitment prevents algebraic PoP forgeries.
	e.Response = ""
	raw, err := json.Marshal(struct {
		Domain, Namespace, Setup, Authority string
		Enrollment                          Enrollment
	}{"lktrs/enrollment-pop/v1", namespace, hexDigest(pin), base64.StdEncoding.EncodeToString(key), e})
	if err != nil {
		return nil, err
	}
	return HashScalar(raw, secfr.Modulus())
}
func CreateEnrollment(x *big.Int, a Account, user, account, namespace string, pin [32]byte, key ed25519.PublicKey, challenge [32]byte) (Enrollment, error) {
	var out Enrollment
	if !canonicalNonzero(x, secfr.Modulus()) || validateAccount(a) != nil || a.D == nil || !validTrustID(user) || !validTrustID(account) || !validTrustID(namespace) || pin == ([32]byte{}) || len(key) != 32 || challenge == ([32]byte{}) {
		return out, errors.New("invalid enrollment input")
	}
	var want secp256k1.G1Affine
	want.ScalarMultiplication(&a.U, x)
	if !want.Equal(&a.Y) {
		return out, errors.New("enrollment secret does not own account")
	}
	r, e := randomNonzero(secfr.Modulus())
	if e != nil {
		return out, e
	}
	var commitment secp256k1.G1Affine
	commitment.ScalarMultiplication(&a.U, r)
	out = Enrollment{user, account, hex.EncodeToString(EncodeSecpPoint(a.U)), hex.EncodeToString(EncodeSecpPoint(a.Y)), scalarHex(a.D), hexDigest(challenge), hex.EncodeToString(EncodeSecpPoint(commitment)), ""}
	c, e := enrollmentChallenge(out, namespace, pin, key)
	if e != nil {
		return Enrollment{}, e
	}
	z := new(big.Int).Mul(c, x)
	z.Add(z, r).Mod(z, secfr.Modulus())
	out.Response = scalarHex(z)
	return out, nil
}
func VerifyEnrollment(e Enrollment, namespace string, pin [32]byte, key ed25519.PublicKey, expectedChallenge [32]byte) (Registration, error) {
	invalid := Registration{}
	if !validTrustID(e.UserID) || !validTrustID(e.AccountID) || !validTrustID(namespace) || len(key) != 32 || pin == ([32]byte{}) || expectedChallenge == ([32]byte{}) || e.Challenge != hexDigest(expectedChallenge) {
		return invalid, errors.New("enrollment identity or challenge mismatch")
	}
	u, err := trustPoint(e.U)
	if err != nil {
		return invalid, err
	}
	y, err := trustPoint(e.Y)
	if err != nil {
		return invalid, err
	}
	d, err := trustScalar(e.D, true)
	if err != nil {
		return invalid, err
	}
	a := Account{U: u, Y: y, D: d}
	if err = validateAccount(a); err != nil {
		return invalid, err
	}
	r, err := trustPoint(e.Commitment)
	if err != nil {
		return invalid, err
	}
	z, err := trustScalar(e.Response, false)
	if err != nil {
		return invalid, err
	}
	c, err := enrollmentChallenge(e, namespace, pin, key)
	if err != nil {
		return invalid, err
	}
	var left, right, cy secp256k1.G1Affine
	left.ScalarMultiplication(&u, z)
	cy.ScalarMultiplication(&y, c)
	right.Add(&r, &cy)
	if !left.Equal(&right) {
		return invalid, errors.New("invalid enrollment proof of possession")
	}
	return Registration{e.UserID, a}, nil
}

type RegistryAuthorization struct {
	Format         string       `json:"format"`
	Namespace      string       `json:"namespace"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	Epoch          uint64       `json:"epoch"`
	NotBefore      int64        `json:"not_before"`
	NotAfter       int64        `json:"not_after"`
	Issue          string       `json:"issue"`
	K              uint32       `json:"k"`
	Entries        []Enrollment `json:"entries"`
}

func registryRegistrations(a RegistryAuthorization, key ed25519.PublicKey) ([]Registration, error) {
	pin, err := ParseDigest(a.ManifestSHA256)
	if err != nil {
		return nil, err
	}
	if a.Format != "lktrs/registry-authorization/v1" || !validTrustID(a.Namespace) || a.Epoch == 0 || a.K == 0 || !validTrustTime(a.NotBefore, a.NotAfter, a.NotBefore) || len(a.Entries) == 0 || len(a.Entries) > 65536 {
		return nil, errors.New("invalid registry authorization")
	}
	if _, err = decodeIssue(a.Issue); err != nil {
		return nil, err
	}
	entries := make([]Registration, len(a.Entries))
	ids := map[string]bool{}
	for i, e := range a.Entries {
		if ids[e.AccountID] {
			return nil, errors.New("duplicate account id")
		}
		ids[e.AccountID] = true
		challenge, err := ParseDigest(e.Challenge)
		if err != nil {
			return nil, err
		}
		entries[i], err = VerifyEnrollment(e, a.Namespace, pin, key, challenge)
		if err != nil {
			return nil, err
		}
	}
	if _, err = NewRegistry(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// SignRegistryAuthorization requires the authority to have separately verified
// each identity and its issued one-time enrollment challenge. It rechecks PoPs
// and registry consistency. Revoke by issuing a new epoch without the user and
// distributing that exact epoch in trusted policies; old snapshots are historical.
func SignRegistryAuthorization(a RegistryAuthorization, signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("missing registry signer")
	}
	key, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("registry signer must use Ed25519")
	}
	if _, e := registryRegistrations(a, key); e != nil {
		return nil, e
	}
	return authoritySign(a, signer)
}

type AuthorizedVerifier struct {
	loaded   *LoadedSetup
	policy   TrustPolicy
	approval []byte
}

func LoadAuthorizedVerifier(dir string, policy TrustPolicy, approval []byte, now int64) (*AuthorizedVerifier, error) {
	if e := verifySetupApproval(policy, approval, now); e != nil {
		return nil, e
	}
	pin, _ := ParseDigest(policy.ManifestSHA256)
	loaded, e := LoadPublicSetup(dir, pin)
	if e != nil {
		return nil, e
	}
	return &AuthorizedVerifier{loaded: loaded, policy: policy, approval: append([]byte{}, approval...)}, nil
}
func authorizedContext(params Params, policy TrustPolicy, raw []byte, now int64) (VerificationContext, Registry, error) {
	fail := func(e error) (VerificationContext, Registry, error) { return VerificationContext{}, Registry{}, e }
	if e := policy.validate(); e != nil {
		return fail(e)
	}
	key, _ := authorityKey(policy.RegistryAuthority)
	var a RegistryAuthorization
	if e := authorityVerify(raw, key, &a); e != nil {
		return fail(e)
	}
	if a.Namespace != policy.Namespace || a.ManifestSHA256 != policy.ManifestSHA256 || a.Epoch != policy.RegistryEpoch || a.Issue != policy.Issue || a.K != policy.K || !validTrustTime(a.NotBefore, a.NotAfter, now) {
		return fail(errors.New("registry authority scope, epoch, policy or validity mismatch"))
	}
	if len(a.Entries) > len(params.Powers)-1 {
		return fail(errors.New("registry exceeds setup capacity"))
	}
	entries, e := registryRegistrations(a, key)
	if e != nil {
		return fail(e)
	}
	registry, e := NewRegistry(entries)
	if e != nil {
		return fail(e)
	}
	accounts := make([]Account, len(entries))
	for i, e := range entries {
		accounts[i] = e.Account
		accounts[i].D = nil
	}
	issue, _ := decodeIssue(a.Issue)
	ctx, e := NewVerificationContext(params, accounts, issue, a.K)
	return ctx, registry, e
}

// Verify authenticates the expected ring/issue/quota before verifying a proof.
// There is no fallback to a ring supplied by the candidate signature.
func (v *AuthorizedVerifier) Verify(registry []byte, message []byte, sig Signed, now int64) error {
	if v == nil || v.loaded == nil {
		return errors.New("missing authorized verifier")
	}
	if e := verifySetupApproval(v.policy, v.approval, now); e != nil {
		return e
	}
	ctx, _, e := authorizedContext(v.loaded.Parameters, v.policy, registry, now)
	if e != nil {
		return e
	}
	return v.loaded.Verifier.Verify(ctx, message, sig)
}

// RegistryDigest is suitable for a caller's separately authenticated audit log.
func RegistryDigest(raw []byte) [32]byte { return sha256.Sum256(raw) }

// Trace verifies two signatures under the same authorized current snapshot and
// resolves only against that authority's enrolled labels. Historical/cross-ring
// tracing requires separately authenticated compatible snapshots; it is not
// inferred from an attacker-provided registry.
func (v *AuthorizedVerifier) Trace(registry, messageA []byte, sigA Signed, messageB []byte, sigB Signed, now int64) (TraceResult, error) {
	invalid := TraceResult{Status: TraceInvalid}
	if v == nil || v.loaded == nil {
		return invalid, errors.New("missing authorized verifier")
	}
	if e := verifySetupApproval(v.policy, v.approval, now); e != nil {
		return invalid, e
	}
	ctx, enrolled, e := authorizedContext(v.loaded.Parameters, v.policy, registry, now)
	if e != nil {
		return invalid, e
	}
	return v.loaded.Verifier.Trace(ctx, messageA, sigA, ctx, messageB, sigB, enrolled)
}
