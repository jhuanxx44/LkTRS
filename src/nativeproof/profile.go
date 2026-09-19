package nativeproof

// This host profile uses separate BN254 and secp256k1 scalar domains. It is an
// explicit parameter profile, not an adapter for the legacy PBC fixtures.
import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

const (
	MemberDomain    = "lktrs/member/v1"
	ChallengeDomain = "lktrs/challenge/v1"
	RingDomain      = "lktrs/ring/v1"
	NymDST          = "LKTRS-BN254-NYM-V1"
	IssueDST        = "LKTRS-SECP256K1-ISSUE-V1"
)

// Params contains only public q-SDH material. Powers[i] = [tau^i]G.
// Setup deliberately retains neither tau nor a signing authority.
type Params struct {
	G      bn254.G1Affine
	H      bn254.G2Affine
	HTau   bn254.G2Affine
	Powers []bn254.G1Affine
}

type Account struct {
	U secp256k1.G1Affine
	Y secp256k1.G1Affine
	// D is optional public account metadata. If present it must be canonical,
	// nonzero, and satisfy U=[D]u. The secret X is never account metadata.
	D *big.Int
}

type Statement struct {
	V             bn254.G1Affine
	Nym           bn254.G1Affine
	S             secp256k1.G1Affine
	T             secp256k1.G1Affine
	Issue         [32]byte
	RingDigest    [32]byte
	MessageDigest [32]byte
	Timestamp     uint64
	K             uint32
	R             *big.Int
}

type SecretWitness struct {
	X       *big.Int
	D       *big.Int
	Account Account
	W       bn254.G1Affine
	Counter uint32
}

// Profile groups the host-side public setup. Each returned snapshot owns its
// account/parameter copies, so failed updates cannot alter an older snapshot.
type Profile struct{ Parameters Params }

func NewProfile(capacity int) (Profile, error) {
	p, err := Setup(capacity)
	if err != nil {
		return Profile{}, err
	}
	return Profile{Parameters: p}, nil
}

func (p Profile) Snapshot(accounts []Account) (Snapshot, error) {
	return NewSnapshot(p.Parameters, accounts)
}

func canonicalNonzero(n, modulus *big.Int) bool {
	return n != nil && n.Sign() > 0 && n.Cmp(modulus) < 0
}

func randomNonzero(modulus *big.Int) (*big.Int, error) {
	upper := new(big.Int).Sub(modulus, big.NewInt(1))
	n, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// Setup creates a bounded public powers sequence with the system CSPRNG. The
// local tau variable is dropped before returning. Go big.Int and GC do not
// guarantee forensic erasure; this function is not an audited MPC ceremony.
func Setup(capacity int) (Params, error) {
	if capacity < 1 || capacity > 1<<16 {
		return Params{}, errors.New("setup capacity must be in [1,65536]")
	}
	tau, err := randomNonzero(bnfr.Modulus())
	if err != nil {
		return Params{}, fmt.Errorf("setup randomness: %w", err)
	}
	_, _, g, h := bn254.Generators()
	p := Params{G: g, H: h, Powers: make([]bn254.G1Affine, capacity+1)}
	p.HTau.ScalarMultiplication(&h, tau)
	power := big.NewInt(1)
	for i := range p.Powers {
		p.Powers[i].ScalarMultiplication(&g, power)
		power.Mul(power, tau).Mod(power, bnfr.Modulus())
	}
	tau.SetInt64(0)
	power.SetInt64(0)
	return p, nil
}

func goodBN(p bn254.G1Affine) bool       { return !p.IsInfinity() && p.IsOnCurve() && p.IsInSubGroup() }
func goodBN2(p bn254.G2Affine) bool      { return !p.IsInfinity() && p.IsOnCurve() && p.IsInSubGroup() }
func goodSecp(p secp256k1.G1Affine) bool { return !p.IsInfinity() && p.IsOnCurve() && p.IsInSubGroup() }

// ValidateParams rejects malformed or inconsistent SRS data. This checks
// algebraic consistency, not whether anybody knows the setup trapdoor.
func ValidateParams(p Params) error {
	if len(p.Powers) < 2 || len(p.Powers) > (1<<16)+1 {
		return errors.New("invalid powers length")
	}
	if !goodBN(p.G) || !goodBN2(p.H) || !goodBN2(p.HTau) {
		return errors.New("invalid setup point")
	}
	_, _, g, h := bn254.Generators()
	if !p.G.Equal(&g) || !p.H.Equal(&h) || !p.Powers[0].Equal(&p.G) {
		return errors.New("unexpected setup generators")
	}
	for i := range p.Powers {
		if !goodBN(p.Powers[i]) {
			return fmt.Errorf("invalid powers point %d", i)
		}
		if i == 0 {
			continue
		}
		var negPrev bn254.G1Affine
		negPrev.Neg(&p.Powers[i-1])
		ok, err := bn254.PairingCheck([]bn254.G1Affine{p.Powers[i], negPrev}, []bn254.G2Affine{p.H, p.HTau})
		if err != nil || !ok {
			return fmt.Errorf("inconsistent powers at %d", i)
		}
	}
	return nil
}

// HashScalar is SHA-256 interpreted as a big-endian integer modulo modulus.
// Zero is rejected; callers must not silently change the preimage to retry.
func HashScalar(data []byte, modulus *big.Int) (*big.Int, error) {
	if modulus == nil || modulus.Cmp(big.NewInt(2)) < 0 {
		return nil, errors.New("invalid scalar modulus")
	}
	sum := sha256.Sum256(data)
	n := new(big.Int).SetBytes(sum[:])
	n.Mod(n, modulus)
	if n.Sign() == 0 {
		return nil, errors.New("hash reduced to zero")
	}
	return n, nil
}

// EncodeBNPoint and EncodeSecpPoint produce fixed-width, big-endian affine
// x||y coordinates (64 bytes). Callers reject infinity before hashing them.
func EncodeBNPoint(p bn254.G1Affine) []byte {
	x, y := p.X.Bytes(), p.Y.Bytes()
	out := make([]byte, 64)
	copy(out[:32], x[:])
	copy(out[32:], y[:])
	return out
}
func EncodeSecpPoint(p secp256k1.G1Affine) []byte {
	x, y := p.X.Bytes(), p.Y.Bytes()
	out := make([]byte, 64)
	copy(out[:32], x[:])
	copy(out[32:], y[:])
	return out
}

func Seeds(x *big.Int, issue [32]byte) (s, t *big.Int, err error) {
	if !canonicalNonzero(x, secfr.Modulus()) {
		return nil, nil, errors.New("x is not a canonical nonzero secp scalar")
	}
	data := make([]byte, 65)
	x.FillBytes(data[:32])
	copy(data[32:64], issue[:])
	s, err = HashScalar(data, secfr.Modulus())
	if err != nil {
		return nil, nil, err
	}
	data[64] = 1
	t, err = HashScalar(data, secfr.Modulus())
	if err != nil {
		return nil, nil, err
	}
	return s, t, nil
}

var basesOnce sync.Once
var fixedBases [3]bn254.G1Affine
var basesError error

func Bases() ([3]bn254.G1Affine, error) {
	basesOnce.Do(func() {
		for i, label := range []string{"g0", "g1", "g2"} {
			fixedBases[i], basesError = bn254.HashToG1([]byte(label), []byte(NymDST))
			if basesError != nil {
				return
			}
			if !goodBN(fixedBases[i]) {
				basesError = errors.New("hash-derived nym base is invalid")
				return
			}
		}
	})
	return fixedBases, basesError
}

func IssueBase(issue [32]byte) (secp256k1.G1Affine, error) {
	p, err := secp256k1.HashToG1(issue[:], []byte(IssueDST))
	if err != nil {
		return p, err
	}
	if !goodSecp(p) {
		return p, errors.New("invalid issue base")
	}
	return p, nil
}

// TraceKey is the per-user value recovered by the duplicate-counter algebra.
// It never attempts to recover x from a group point.
func TraceKey(x *big.Int) (secp256k1.G1Affine, error) {
	if !canonicalNonzero(x, secfr.Modulus()) {
		return secp256k1.G1Affine{}, errors.New("invalid user secret")
	}
	_, u := secp256k1.Generators()
	var key secp256k1.G1Affine
	key.ScalarMultiplication(&u, x)
	return key, nil
}

func NewAccount(x, d *big.Int) (Account, error) {
	if !canonicalNonzero(x, secfr.Modulus()) || !canonicalNonzero(d, secfr.Modulus()) {
		return Account{}, errors.New("account scalars must be canonical nonzero secp scalars")
	}
	_, u := secp256k1.Generators()
	a := Account{D: new(big.Int).Set(d)}
	a.U.ScalarMultiplication(&u, d)
	a.Y.ScalarMultiplication(&a.U, x)
	return a, validateAccount(a)
}

// KeyGen reuses an existing user secret if provided and samples a fresh account
// exponent. The returned secret and Account.D are independent copies.
func KeyGen(existingX *big.Int) (Account, *big.Int, error) {
	var x *big.Int
	var err error
	if existingX == nil {
		x, err = randomNonzero(secfr.Modulus())
		if err != nil {
			return Account{}, nil, err
		}
	} else {
		if !canonicalNonzero(existingX, secfr.Modulus()) {
			return Account{}, nil, errors.New("invalid existing user secret")
		}
		x = new(big.Int).Set(existingX)
	}
	d, err := randomNonzero(secfr.Modulus())
	if err != nil {
		return Account{}, nil, err
	}
	a, err := NewAccount(x, d)
	if err != nil {
		return Account{}, nil, err
	}
	return a, x, nil
}

func validateAccount(a Account) error {
	if !goodSecp(a.U) || !goodSecp(a.Y) {
		return errors.New("account contains invalid or identity point")
	}
	if a.D != nil {
		if !canonicalNonzero(a.D, secfr.Modulus()) {
			return errors.New("invalid public account d")
		}
		_, u := secp256k1.Generators()
		var want secp256k1.G1Affine
		want.ScalarMultiplication(&u, a.D)
		if !want.Equal(&a.U) {
			return errors.New("account U does not match d")
		}
	}
	return nil
}

func Member(a Account) (*big.Int, error) {
	if err := validateAccount(a); err != nil {
		return nil, err
	}
	data := append([]byte(MemberDomain), EncodeSecpPoint(a.U)...)
	data = append(data, EncodeSecpPoint(a.Y)...)
	return HashScalar(data, bnfr.Modulus())
}

func membersOf(accounts []Account) ([]*big.Int, error) {
	if len(accounts) == 0 || uint64(len(accounts)) > uint64(^uint32(0)) {
		return nil, errors.New("ring must be nonempty and fit uint32 count")
	}
	members := make([]*big.Int, len(accounts))
	seen := make(map[string]bool, len(accounts))
	for i, a := range accounts {
		member, err := Member(a)
		if err != nil {
			return nil, fmt.Errorf("account %d: %w", i, err)
		}
		key := member.String()
		if seen[key] {
			return nil, errors.New("duplicate member handle")
		}
		seen[key] = true
		members[i] = member
	}
	return members, nil
}

func RingDigest(accounts []Account) ([32]byte, error) {
	if _, err := membersOf(accounts); err != nil {
		return [32]byte{}, err
	}
	data := []byte(RingDomain)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(accounts)))
	data = append(data, count[:]...)
	for _, a := range accounts {
		data = append(data, EncodeSecpPoint(a.U)...)
		data = append(data, EncodeSecpPoint(a.Y)...)
	}
	return sha256.Sum256(data), nil
}

func Challenge(st Statement) (*big.Int, error) {
	if st.K == 0 || !goodBN(st.Nym) {
		return nil, errors.New("invalid challenge k or nym")
	}
	data := append([]byte(ChallengeDomain), st.Issue[:]...)
	data = append(data, st.RingDigest[:]...)
	data = append(data, st.MessageDigest[:]...)
	data = append(data, EncodeBNPoint(st.Nym)...)
	var tail [12]byte
	binary.BigEndian.PutUint64(tail[:8], st.Timestamp)
	binary.BigEndian.PutUint32(tail[8:], st.K)
	data = append(data, tail[:]...)
	return HashScalar(data, secfr.Modulus())
}

// Polynomial coefficients are in ascending degree, all in BN254 Fr.
func memberPolynomial(members []*big.Int) []*big.Int {
	coefficients := []*big.Int{big.NewInt(1)}
	mod := bnfr.Modulus()
	for _, member := range members {
		next := make([]*big.Int, len(coefficients)+1)
		for i := range next {
			next[i] = new(big.Int)
		}
		for i, c := range coefficients {
			product := new(big.Int).Mul(c, member)
			next[i].Add(next[i], product).Mod(next[i], mod)
			next[i+1].Add(next[i+1], c).Mod(next[i+1], mod)
		}
		coefficients = next
	}
	return coefficients
}

func combinePowers(p Params, members []*big.Int) (bn254.G1Affine, error) {
	if len(members) >= len(p.Powers) {
		return bn254.G1Affine{}, errors.New("ring exceeds public powers capacity")
	}
	var sum bn254.G1Affine
	sum.SetInfinity()
	for i, c := range memberPolynomial(members) {
		var term, next bn254.G1Affine
		term.ScalarMultiplication(&p.Powers[i], c)
		next.Add(&sum, &term)
		sum = next
	}
	if !goodBN(sum) {
		return bn254.G1Affine{}, errors.New("accumulator polynomial has an identity result")
	}
	return sum, nil
}

func Accumulate(p Params, accounts []Account) (bn254.G1Affine, error) {
	if err := ValidateParams(p); err != nil {
		return bn254.G1Affine{}, err
	}
	// An empty accumulator is G; ring signing itself still requires nonempty.
	if len(accounts) == 0 {
		return p.G, nil
	}
	members, err := membersOf(accounts)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	return combinePowers(p, members)
}

func MembershipWitness(p Params, accounts []Account, selectedIdx int) (bn254.G1Affine, error) {
	if err := ValidateParams(p); err != nil {
		return bn254.G1Affine{}, err
	}
	if selectedIdx < 0 || selectedIdx >= len(accounts) {
		return bn254.G1Affine{}, errors.New("selected index out of range")
	}
	members, err := membersOf(accounts)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	if len(members) >= len(p.Powers) {
		return bn254.G1Affine{}, errors.New("ring exceeds capacity")
	}
	remaining := append([]*big.Int{}, members[:selectedIdx]...)
	remaining = append(remaining, members[selectedIdx+1:]...)
	return combinePowers(p, remaining)
}

func VerifyMembership(p Params, v, w bn254.G1Affine, member *big.Int) bool {
	if !canonicalNonzero(member, bnfr.Modulus()) || !goodBN(v) || !goodBN(w) || ValidateParams(p) != nil {
		return false
	}
	var ha, hat bn254.G2Affine
	ha.ScalarMultiplication(&p.H, member)
	hat.Add(&ha, &p.HTau)
	if !goodBN2(hat) {
		return false
	}
	var negV bn254.G1Affine
	negV.Neg(&v)
	ok, err := bn254.PairingCheck([]bn254.G1Affine{w, negV}, []bn254.G2Affine{hat, p.H})
	return err == nil && ok
}

func MakeStatement(p Params, accounts []Account, selectedIdx int, x, d *big.Int, issue, messageDigest [32]byte, timestamp uint64, k, counter uint32) (Statement, SecretWitness, error) {
	if k == 0 || counter >= k {
		return Statement{}, SecretWitness{}, errors.New("counter must be in [0,k)")
	}
	if selectedIdx < 0 || selectedIdx >= len(accounts) {
		return Statement{}, SecretWitness{}, errors.New("selected index out of range")
	}
	selected, err := NewAccount(x, d)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	if !selected.U.Equal(&accounts[selectedIdx].U) || !selected.Y.Equal(&accounts[selectedIdx].Y) {
		return Statement{}, SecretWitness{}, errors.New("secret does not match selected account")
	}
	if accounts[selectedIdx].D != nil && accounts[selectedIdx].D.Cmp(d) != 0 {
		return Statement{}, SecretWitness{}, errors.New("d differs from selected metadata")
	}
	v, err := Accumulate(p, accounts)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	w, err := MembershipWitness(p, accounts, selectedIdx)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	ring, err := RingDigest(accounts)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	s, t, err := Seeds(x, issue)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	bases, err := Bases()
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	nym := bn254.G1Affine{}
	nym.SetInfinity()
	for i, seed := range []*big.Int{s, t, x} {
		residue := new(big.Int).Mod(new(big.Int).Set(seed), bnfr.Modulus())
		var term, next bn254.G1Affine
		term.ScalarMultiplication(&bases[i], residue)
		next.Add(&nym, &term)
		nym = next
	}
	if !goodBN(nym) {
		return Statement{}, SecretWitness{}, errors.New("identity nym")
	}
	st := Statement{V: v, Nym: nym, Issue: issue, RingDigest: ring, MessageDigest: messageDigest, Timestamp: timestamp, K: k}
	st.R, err = Challenge(st)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	ut, err := IssueBase(issue)
	if err != nil {
		return Statement{}, SecretWitness{}, err
	}
	mod := secfr.Modulus()
	offset := new(big.Int).SetUint64(uint64(counter) + 1)
	ds := new(big.Int).Add(s, offset)
	ds.Mod(ds, mod)
	dt := new(big.Int).Add(t, offset)
	dt.Mod(dt, mod)
	if ds.Sign() == 0 || dt.Sign() == 0 {
		return Statement{}, SecretWitness{}, errors.New("zero seed/counter denominator")
	}
	is := new(big.Int).ModInverse(ds, mod)
	it := new(big.Int).ModInverse(dt, mod)
	st.S.ScalarMultiplication(&ut, is)
	_, u := secp256k1.Generators()
	var ux, rt secp256k1.G1Affine
	ux.ScalarMultiplication(&u, x)
	exponent := new(big.Int).Mul(st.R, it)
	exponent.Mod(exponent, mod)
	rt.ScalarMultiplication(&ut, exponent)
	st.T.Add(&ux, &rt)
	if !goodSecp(st.S) || !goodSecp(st.T) {
		return Statement{}, SecretWitness{}, errors.New("identity S or T")
	}
	return st, SecretWitness{X: new(big.Int).Set(x), D: new(big.Int).Set(d), Account: cloneAccount(selected), W: w, Counter: counter}, nil
}

func cloneAccount(a Account) Account {
	if a.D != nil {
		a.D = new(big.Int).Set(a.D)
	}
	return a
}
func cloneAccounts(in []Account) []Account {
	out := make([]Account, len(in))
	for i, a := range in {
		out[i] = cloneAccount(a)
	}
	return out
}
func cloneParams(p Params) Params { p.Powers = append([]bn254.G1Affine{}, p.Powers...); return p }

// Snapshot provides immutable public-set updates. Join and Exit either return
// a complete newly recomputed snapshot or leave the receiver unchanged. An
// empty snapshot is valid with V=G; it can be populated again using Join.
// RingDigest and MakeStatement deliberately reject empty signing rings.
type Snapshot struct {
	params   Params
	accounts []Account
	value    bn254.G1Affine
}

// NewSnapshot validates the supplied public powers even for an empty account
// list, then retains deep copies of the SRS slice and optional account scalars.
func NewSnapshot(p Params, accounts []Account) (Snapshot, error) {
	ownedP, ownedAccounts := cloneParams(p), cloneAccounts(accounts)
	v, err := Accumulate(ownedP, ownedAccounts)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{params: ownedP, accounts: ownedAccounts, value: v}, nil
}
func (s Snapshot) Accounts() []Account   { return cloneAccounts(s.accounts) }
func (s Snapshot) Value() bn254.G1Affine { return s.value }
func (s Snapshot) Params() Params        { return cloneParams(s.params) }
func (s Snapshot) Join(a Account) (Snapshot, error) {
	return NewSnapshot(s.params, append(cloneAccounts(s.accounts), cloneAccount(a)))
}
func (s Snapshot) Exit(member *big.Int) (Snapshot, error) {
	if !canonicalNonzero(member, bnfr.Modulus()) {
		return Snapshot{}, errors.New("invalid exit member")
	}
	keep := make([]Account, 0, len(s.accounts))
	found := false
	for _, a := range s.accounts {
		m, err := Member(a)
		if err != nil {
			return Snapshot{}, err
		}
		if m.Cmp(member) == 0 {
			found = true
			continue
		}
		keep = append(keep, cloneAccount(a))
	}
	if !found {
		return Snapshot{}, errors.New("exit member not found")
	}
	return NewSnapshot(s.params, keep)
}
