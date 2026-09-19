package nativeproof

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"math/big"
	"sync"
)

// Signer owns one user's secret and an issue-scoped counter shared by all of
// its accounts. Restart persistence and authenticated registration are the
// caller's responsibility; this is a research wallet, not a production wallet.
type Signer struct {
	mu   sync.Mutex
	x    *big.Int
	next map[[32]byte]uint32
}

func NewSigner(x *big.Int) (*Signer, error) {
	if !canonicalNonzero(x, fr.Modulus()) {
		return nil, errors.New("invalid user secret")
	}
	return &Signer{x: newBig(x), next: make(map[[32]byte]uint32)}, nil
}
func (s *Signer) Sign(p *Prover, ring Snapshot, account int, issue [32]byte, k uint32, message []byte, ts uint64) (Signed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil {
		return Signed{}, errors.New("missing prover")
	}
	if account < 0 || account >= len(ring.accounts) {
		return Signed{}, errors.New("account index outside ring")
	}
	count := s.next[issue]
	if k == 0 || count >= k {
		return Signed{}, errors.New("user quota exhausted")
	}
	d := ring.accounts[account].D
	if d == nil {
		return Signed{}, errors.New("missing account exponent")
	}
	st, w, err := MakeStatement(ring.params, ring.accounts, account, s.x, d, issue, sha256.Sum256(message), ts, k, count)
	if err != nil {
		return Signed{}, err
	}
	sig, err := p.Prove(ring.params, st, w)
	if err != nil {
		return Signed{}, err
	}
	s.next[issue] = count + 1
	return sig, nil
}
func (s *Signer) NextCounter(issue [32]byte) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next[issue]
}

type Registration struct {
	UserID  string
	Account Account
}
type Registry struct{ entries []Registration }

func NewRegistry(entries []Registration) (Registry, error) {
	if len(entries) == 0 {
		return Registry{}, errors.New("empty registry")
	}
	out := Registry{entries: make([]Registration, len(entries))}
	seen := map[string]bool{}
	traceOwners := map[string]string{}
	userKeys := map[string]string{}
	for i, e := range entries {
		if e.UserID == "" || e.Account.D == nil {
			return Registry{}, errors.New("registration needs user id and public d")
		}
		if err := validateAccount(e.Account); err != nil {
			return Registry{}, err
		}
		member, err := Member(e.Account)
		if err != nil {
			return Registry{}, err
		}
		key := member.String()
		if seen[key] {
			return Registry{}, errors.New("duplicate registered account")
		}
		seen[key] = true
		inverse := new(big.Int).ModInverse(e.Account.D, fr.Modulus())
		var ux secp256k1.G1Affine
		ux.ScalarMultiplication(&e.Account.Y, inverse)
		trace := string(EncodeSecpPoint(ux))
		if owner, ok := traceOwners[trace]; ok && owner != e.UserID {
			return Registry{}, errors.New("same trace key registered to different users")
		}
		if previous, ok := userKeys[e.UserID]; ok && previous != trace {
			return Registry{}, errors.New("one user has inconsistent secrets")
		}
		traceOwners[trace] = e.UserID
		userKeys[e.UserID] = trace
		out.entries[i] = Registration{e.UserID, cloneAccount(e.Account)}
	}
	return out, nil
}
func (r Registry) Resolve(ux secp256k1.G1Affine) (string, error) {
	if !goodSecp(ux) {
		return "", errors.New("invalid extracted trace key")
	}
	for _, e := range r.entries {
		var y secp256k1.G1Affine
		y.ScalarMultiplication(&ux, e.Account.D)
		if y.Equal(&e.Account.Y) {
			return e.UserID, nil
		}
	}
	return "", errors.New("unregistered extracted trace key")
}

// Revocation exits every registered account for a user in the current ring.
// Unknown-user and failed updates leave the input snapshot unchanged.
func (r Registry) RevokeUser(ring Snapshot, user string) (Snapshot, error) {
	found := false
	members := map[string]bool{}
	for _, e := range r.entries {
		if e.UserID == user {
			found = true
			m, err := Member(e.Account)
			if err != nil {
				return Snapshot{}, err
			}
			members[m.String()] = true
		}
	}
	if !found {
		return Snapshot{}, errors.New("unregistered user")
	}
	remaining := make([]Account, 0, len(ring.accounts))
	for _, a := range ring.accounts {
		m, err := Member(a)
		if err != nil {
			return Snapshot{}, err
		}
		if !members[m.String()] {
			remaining = append(remaining, a)
		}
	}
	return NewSnapshot(ring.params, remaining)
}

type TraceStatus string

const (
	TraceLegal   TraceStatus = "legal"
	TraceReplay  TraceStatus = "replay"
	TraceInvalid TraceStatus = "invalid"
	TraceTraced  TraceStatus = "traced"
)

type TraceResult struct {
	Status TraceStatus
	UserID string
	Key    secp256k1.G1Affine
}

func (v *Verifier) Link(a VerificationContext, ma []byte, sa Signed, b VerificationContext, mb []byte, sb Signed) (bool, error) {
	if err := v.Verify(a, ma, sa); err != nil {
		return false, err
	}
	if err := v.Verify(b, mb, sb); err != nil {
		return false, err
	}
	return a.issue == b.issue && sa.Statement.Nym.Equal(&sb.Statement.Nym), nil
}
func (v *Verifier) Trace(a VerificationContext, ma []byte, sa Signed, b VerificationContext, mb []byte, sb Signed, registry Registry) (TraceResult, error) {
	invalid := TraceResult{Status: TraceInvalid}
	if err := v.Verify(a, ma, sa); err != nil {
		return invalid, err
	}
	if err := v.Verify(b, mb, sb); err != nil {
		return invalid, err
	}
	if a.issue != b.issue || a.k != b.k || !sa.Statement.Nym.Equal(&sb.Statement.Nym) {
		return invalid, errors.New("trace requires same issue, quota and nym")
	}
	x, y := sa.Statement, sb.Statement
	if !x.S.Equal(&y.S) {
		return TraceResult{Status: TraceLegal}, nil
	}
	diff := new(big.Int).Sub(y.R, x.R)
	diff.Mod(diff, fr.Modulus())
	if diff.Sign() == 0 {
		if x.T.Equal(&y.T) {
			return TraceResult{Status: TraceReplay}, nil
		}
		return invalid, errors.New("serial collision with equal challenges")
	}
	var aTag, bTag, delta, ux secp256k1.G1Affine
	aTag.ScalarMultiplication(&x.T, y.R)
	bTag.ScalarMultiplication(&y.T, x.R)
	delta.Sub(&aTag, &bTag)
	ux.ScalarMultiplication(&delta, new(big.Int).ModInverse(diff, fr.Modulus()))
	user, err := registry.Resolve(ux)
	if err != nil {
		return invalid, fmt.Errorf("trace lookup: %w", err)
	}
	return TraceResult{Status: TraceTraced, UserID: user, Key: ux}, nil
}
