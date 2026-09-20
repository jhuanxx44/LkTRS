package nativeproof

// A local encrypted research wallet. The wrapping key must be provisioned by an
// external secret store; this package never writes it. This is not an HSM: the
// witness secret must enter the prover's memory. File rollback, cloned wallets,
// hostile OS/admin access and forensic erasure require external controls.
import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"golang.org/x/crypto/chacha20poly1305"
)

const vaultMagic = "LKTRSV02"
const maxVaultBytes = 1 << 20

type vaultCounter struct {
	Next uint32 `json:"next"`
	K    uint32 `json:"k"`
}
type vaultState struct {
	X        string                  `json:"x"`
	Counters map[string]vaultCounter `json:"counters"`
}

type SignerVault struct {
	mu   sync.Mutex
	path string
	id   [32]byte
	key  []byte
}

func newSignerVault(path string, key []byte, id [32]byte) (*SignerVault, error) {
	if len(key) != 32 || bytes.Equal(key, make([]byte, 32)) || id == ([32]byte{}) || path == "" {
		return nil, errors.New("vault needs path, nonzero id and external 32-byte wrapping key")
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	return &SignerVault{path: absolute, id: id, key: append([]byte{}, key...)}, nil
}
func (v *SignerVault) lock() (func(), error) {
	v.mu.Lock()
	if len(v.key) != 32 {
		v.mu.Unlock()
		return nil, errors.New("vault is closed")
	}
	// O_NOFOLLOW protects the stable lock inode from symlink substitution. The
	// parent directory must be trusted and lock files must never be deleted while
	// any wallet handle exists. Flock serializes cooperating local processes.
	fd, e := syscall.Open(v.path+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		v.mu.Unlock()
		return nil, e
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX); e != nil {
		_ = syscall.Close(fd)
		v.mu.Unlock()
		return nil, e
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = syscall.Close(fd); v.mu.Unlock() }, nil
}
func (v *SignerVault) aead() (cipher.AEAD, error) {
	// A wallet may reserve up to uint32 counters in each of many issues.
	// XChaCha's 192-bit random nonce covers that lifetime without pretending
	// committed counters account for failed encryption/write attempts.
	return chacha20poly1305.NewX(v.key)
}
func (v *SignerVault) aad() []byte { return append([]byte(vaultMagic), v.id[:]...) }
func (v *SignerVault) read() (vaultState, error) {
	var state vaultState
	stat, e := os.Lstat(v.path)
	if e != nil {
		return state, e
	}
	if stat.Mode().Perm()&0077 != 0 {
		return state, errors.New("vault file must have owner-only permissions")
	}
	raw, e := ReadBoundedFile(v.path, maxVaultBytes)
	if e != nil {
		return state, e
	}
	aead, e := v.aead()
	if e != nil {
		return state, e
	}
	prefix := v.aad()
	if len(raw) < len(prefix)+aead.NonceSize()+aead.Overhead() || !bytes.Equal(raw[:len(prefix)], prefix) {
		return state, errors.New("invalid vault identity or encoding")
	}
	nonce := raw[len(prefix) : len(prefix)+aead.NonceSize()]
	plain, e := aead.Open(nil, nonce, raw[len(prefix)+len(nonce):], prefix)
	if e != nil {
		return state, errors.New("vault authentication failed")
	}
	defer clear(plain)
	if e = strictJSON(plain, &state); e != nil {
		return state, e
	}
	if _, e = trustScalar(state.X, true); e != nil {
		return state, e
	}
	if state.Counters == nil || len(state.Counters) > 10000 {
		return state, errors.New("invalid vault counters")
	}
	for issue, c := range state.Counters {
		if _, e = decodeIssue(issue); e != nil || c.K == 0 || c.Next > c.K {
			return state, errors.New("invalid persisted counter or quota")
		}
	}
	return state, nil
}
func (v *SignerVault) write(state vaultState, create bool) error {
	plain, e := json.Marshal(state)
	if e != nil {
		return e
	}
	defer clear(plain)
	if len(plain) > maxVaultBytes-128 {
		return errors.New("vault state exceeds size budget")
	}
	aead, e := v.aead()
	if e != nil {
		return e
	}
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	prefix := v.aad()
	raw := append(append([]byte{}, prefix...), nonce...)
	raw = aead.Seal(raw, nonce, plain, prefix)
	tmp, e := os.CreateTemp(filepath.Dir(v.path), ".lktrs-vault-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(raw); e != nil {
		_ = tmp.Close()
		return e
	}
	if e = tmp.Sync(); e != nil {
		_ = tmp.Close()
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if create {
		e = os.Link(name, v.path)
	} else {
		e = os.Rename(name, v.path)
	}
	if e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(v.path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func CreateSignerVault(path string, key []byte, id [32]byte, x *big.Int) (*SignerVault, error) {
	if !canonicalNonzero(x, secfr.Modulus()) {
		return nil, errors.New("invalid wallet secret")
	}
	v, e := newSignerVault(path, key, id)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(v.path), 0700); e != nil {
		v.Close()
		return nil, e
	}
	unlock, e := v.lock()
	if e != nil {
		v.Close()
		return nil, e
	}
	e = v.write(vaultState{scalarHex(x), map[string]vaultCounter{}}, true)
	unlock()
	if e != nil {
		v.Close()
		return nil, e
	}
	return v, nil
}
func OpenSignerVault(path string, key []byte, id [32]byte) (*SignerVault, error) {
	v, e := newSignerVault(path, key, id)
	if e != nil {
		return nil, e
	}
	unlock, e := v.lock()
	if e != nil {
		v.Close()
		return nil, e
	}
	_, e = v.read()
	unlock()
	if e != nil {
		v.Close()
		return nil, e
	}
	return v, nil
}

// Close overwrites the held wrapping-key slice on a best-effort basis. It does
// not promise erasure of copies made by the runtime or caller.
func (v *SignerVault) Close() { v.mu.Lock(); defer v.mu.Unlock(); clear(v.key); v.key = nil }
func (v *SignerVault) NextCounter(issue [32]byte) (uint32, error) {
	unlock, e := v.lock()
	if e != nil {
		return 0, e
	}
	defer unlock()
	state, e := v.read()
	if e != nil {
		return 0, e
	}
	return state.Counters[hexDigest(issue)].Next, nil
}
func (v *SignerVault) reserveAndProve(issue [32]byte, k uint32, prove func(*big.Int, uint32) (Signed, error)) (Signed, error) {
	unlock, e := v.lock()
	if e != nil {
		return Signed{}, e
	}
	defer unlock()
	state, e := v.read()
	if e != nil {
		return Signed{}, e
	}
	label := hexDigest(issue)
	counter, exists := state.Counters[label]
	if k == 0 || (exists && counter.K != k) || counter.Next >= k {
		return Signed{}, errors.New("wallet quota exhausted or policy changed")
	}
	if !exists && len(state.Counters) >= 10000 {
		return Signed{}, errors.New("wallet issue limit reached")
	}
	x, e := trustScalar(state.X, true)
	if e != nil {
		return Signed{}, e
	}
	defer x.SetInt64(0)
	state.Counters[label] = vaultCounter{counter.Next + 1, k}
	// Reserve and sync BEFORE releasing a proof. A crash or proving failure burns
	// this slot; restoring a prior encrypted file can still roll it back.
	if e = v.write(state, false); e != nil {
		return Signed{}, fmt.Errorf("reserve wallet counter: %w", e)
	}
	return prove(x, counter.Next)
}
func (v *SignerVault) Sign(p *Prover, ring Snapshot, account int, issue [32]byte, k uint32, message []byte, ts uint64) (Signed, error) {
	if p == nil || account < 0 || account >= len(ring.accounts) || ring.accounts[account].D == nil {
		return Signed{}, errors.New("invalid wallet signing context")
	}
	return v.reserveAndProve(issue, k, func(x *big.Int, count uint32) (Signed, error) {
		st, w, e := MakeStatement(ring.params, ring.accounts, account, x, ring.accounts[account].D, issue, sha256.Sum256(message), ts, k, count)
		if e != nil {
			return Signed{}, e
		}
		return p.Prove(ring.params, st, w)
	})
}
