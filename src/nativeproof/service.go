package nativeproof

// Service is a local research signer/verifier. It uses a framed stdio transport
// but does not define security policy through caller-supplied verification keys.
// setup owns keys, registry and public ring; Verify sees only a public context.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

type Request struct {
	Op              string `json:"op"`
	Capacity        int    `json:"capacity,omitempty"`
	User            string `json:"user,omitempty"`
	Account         string `json:"account,omitempty"`
	Issue           string `json:"issue,omitempty"`
	K               uint32 `json:"k,omitempty"`
	Message         string `json:"message_b64,omitempty"`
	Timestamp       uint64 `json:"timestamp,omitempty"`
	Signature       string `json:"signature_b64,omitempty"`
	SecondMessage   string `json:"second_message_b64,omitempty"`
	SecondSignature string `json:"second_signature_b64,omitempty"`
}
type Response struct {
	OK        bool        `json:"ok"`
	Error     string      `json:"error,omitempty"`
	Version   string      `json:"version,omitempty"`
	Signature string      `json:"signature_b64,omitempty"`
	Verified  bool        `json:"verified,omitempty"`
	Linked    bool        `json:"linked,omitempty"`
	Trace     TraceStatus `json:"trace,omitempty"`
	User      string      `json:"user,omitempty"`
	Members   int         `json:"members"`
}
type Service struct {
	mu        sync.Mutex
	params    Params
	prover    *Prover
	verifier  *Verifier
	users     map[string]*Signer
	accounts  map[string]Registration
	active    map[string]bool
	policies  map[[32]byte]uint32
	revoked   map[string]bool
	seen      map[[32]byte]bool
	statePath string
}

func NewService() *Service {
	return newService("")
}

// NewPersistentService enables the research service's crash-recoverable
// policy/revocation/replay ledger. Private keys and Groth16 setup remain
// process-local; callers must still provision authenticated key custody and a
// durable setup manifest for any stronger deployment claim.
func NewPersistentService(path string) (*Service, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("state path is required")
	}
	s := newService(path)
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

func newService(path string) *Service {
	return &Service{users: map[string]*Signer{}, accounts: map[string]Registration{}, active: map[string]bool{}, policies: map[[32]byte]uint32{}, revoked: map[string]bool{}, seen: map[[32]byte]bool{}, statePath: path}
}

type durableServiceState struct {
	Version  int               `json:"version"`
	Policies map[string]uint32 `json:"policies"`
	Revoked  []string          `json:"revoked"`
	Seen     []string          `json:"seen"`
}

func (s *Service) loadState() error {
	raw, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state durableServiceState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return fmt.Errorf("decode service state: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("trailing service state")
	}
	if state.Version != 1 {
		return errors.New("unsupported service state version")
	}
	for encoded, k := range state.Policies {
		issue, err := decodeIssue(encoded)
		if err != nil || k == 0 {
			return errors.New("invalid persisted issue policy")
		}
		s.policies[issue] = k
	}
	for _, user := range state.Revoked {
		if strings.TrimSpace(user) == "" {
			return errors.New("invalid persisted revoked user")
		}
		s.revoked[user] = true
	}
	for _, encoded := range state.Seen {
		if len(encoded) != 64 {
			return errors.New("invalid persisted replay digest")
		}
		b, err := hex.DecodeString(encoded)
		if err != nil {
			return errors.New("invalid persisted replay digest")
		}
		var digest [32]byte
		copy(digest[:], b)
		s.seen[digest] = true
	}
	return nil
}

func (s *Service) persistState() error {
	if s.statePath == "" {
		return nil
	}
	state := durableServiceState{Version: 1, Policies: map[string]uint32{}, Revoked: []string{}, Seen: []string{}}
	for issue, k := range s.policies {
		state.Policies[hex.EncodeToString(issue[:])] = k
	}
	for user := range s.revoked {
		state.Revoked = append(state.Revoked, user)
	}
	for digest := range s.seen {
		state.Seen = append(state.Seen, hex.EncodeToString(digest[:]))
	}
	sort.Strings(state.Revoked)
	sort.Strings(state.Seen)
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.statePath), ".lktrs-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.statePath); err != nil {
		return err
	}
	// Persist the directory entry as well as the file contents so a crash after
	// rename cannot silently discard the new ledger on filesystems that support
	// directory fsync. The state remains a research ledger, not a transaction DB.
	dir, err := os.Open(filepath.Dir(s.statePath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Service) ring() ([]string, []Account) {
	ids := []string{}
	for id, active := range s.active {
		if active {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	accounts := make([]Account, 0, len(ids))
	for _, id := range ids {
		accounts = append(accounts, cloneAccount(s.accounts[id].Account))
	}
	return ids, accounts
}
func decodeB64(s string) ([]byte, error) {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil {
		return nil, e
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("noncanonical base64")
	}
	return b, nil
}
func decodeIssue(s string) ([32]byte, error) {
	var out [32]byte
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return out, errors.New("issue must be 32 bytes in lowercase hex")
	}
	copy(out[:], b)
	return out, nil
}
func decodeRequest(raw []byte) (Request, error) {
	if !utf8.Valid(raw) {
		return Request{}, errors.New("request is not valid UTF-8")
	}
	if err := rejectDuplicateJSON(raw); err != nil {
		return Request{}, err
	}
	var q Request
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&q); e != nil {
		return q, e
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return q, errors.New("trailing JSON")
	}
	return q, nil
}

func rejectDuplicateJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if seen[name] {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (s *Service) Handle(raw []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, e := decodeRequest(raw)
	var out Response
	if e != nil {
		out = Response{Error: e.Error()}
	} else {
		out, e = s.run(q)
		if e != nil {
			out.OK = false
			out.Error = e.Error()
		} else {
			out.OK = true
		}
	}
	_, ring := s.ring()
	out.Members = len(ring)
	b, _ := json.Marshal(out)
	return b
}
func (s *Service) run(q Request) (Response, error) {
	out := Response{Version: CircuitVersion}
	if q.Op == "info" {
		return out, nil
	}
	if q.Op == "setup" {
		if s.prover != nil {
			return out, errors.New("setup already completed")
		}
		p, e := Setup(q.Capacity)
		if e != nil {
			return out, e
		}
		prover, verifier, e := NewBackend()
		if e != nil {
			return out, e
		}
		s.params = p
		s.prover = prover
		s.verifier = verifier
		if err := s.persistState(); err != nil {
			return out, fmt.Errorf("persist setup state: %w", err)
		}
		return out, nil
	}
	if s.prover == nil {
		return out, errors.New("setup required")
	}
	switch q.Op {
	case "keygen":
		if strings.TrimSpace(q.User) == "" || strings.TrimSpace(q.Account) == "" {
			return out, errors.New("user/account ids required")
		}
		if _, exists := s.accounts[q.Account]; exists {
			return out, errors.New("account exists")
		}
		if s.revoked[q.User] {
			return out, errors.New("user is permanently revoked")
		}
		signer := s.users[q.User]
		var a Account
		if signer == nil {
			key, x, e := KeyGen(nil)
			if e != nil {
				return out, e
			}
			a = key
			signer, e = NewSigner(x)
			if e != nil {
				return out, e
			}
			s.users[q.User] = signer
		} else {
			key, _, e := KeyGen(signer.x)
			if e != nil {
				return out, e
			}
			a = key
		}
		s.accounts[q.Account] = Registration{q.User, a}
		if err := s.persistState(); err != nil {
			delete(s.accounts, q.Account)
			return out, fmt.Errorf("persist keygen state: %w", err)
		}
		return out, nil
	case "join", "exit":
		reg, exists := s.accounts[q.Account]
		if !exists {
			return out, errors.New("account unknown")
		}
		_, accounts := s.ring()
		snap, e := NewSnapshot(s.params, accounts)
		if e != nil {
			return out, e
		}
		if q.Op == "join" {
			if s.revoked[reg.UserID] {
				return out, errors.New("user is permanently revoked")
			}
			if _, e = snap.Join(reg.Account); e != nil {
				return out, e
			}
			s.active[q.Account] = true
		} else {
			if !s.active[q.Account] {
				return out, errors.New("account inactive")
			}
			member, e := Member(reg.Account)
			if e != nil {
				return out, e
			}
			if _, e = snap.Exit(member); e != nil {
				return out, e
			}
			s.active[q.Account] = false
		}
		if err := s.persistState(); err != nil {
			return out, fmt.Errorf("persist ring state: %w", err)
		}
		return out, nil
	case "revoke_user":
		if _, ok := s.users[q.User]; !ok {
			return out, errors.New("unknown user")
		}
		for id, r := range s.accounts {
			if r.UserID == q.User {
				s.active[id] = false
			}
		}
		s.revoked[q.User] = true
		if err := s.persistState(); err != nil {
			return out, fmt.Errorf("persist revocation state: %w", err)
		}
		return out, nil
	}
	issue, e := decodeIssue(q.Issue)
	if e != nil {
		return out, e
	}
	msg, e := decodeB64(q.Message)
	if e != nil {
		return out, e
	}
	if e = s.policy(issue, q.K, q.Op == "sign"); e != nil {
		return out, e
	}
	ids, ring := s.ring()
	ctx, e := NewVerificationContext(s.params, ring, issue, q.K)
	if e != nil {
		return out, e
	}
	if q.Op == "sign" {
		idx := -1
		for i, id := range ids {
			if id == q.Account {
				idx = i
			}
		}
		if idx < 0 {
			return out, errors.New("account not in current ring")
		}
		snap, e := NewSnapshot(s.params, ring)
		if e != nil {
			return out, e
		}
		signed, e := s.users[s.accounts[q.Account].UserID].Sign(s.prover, snap, idx, issue, q.K, msg, q.Timestamp)
		if e != nil {
			return out, e
		}
		enc, e := MarshalSigned(signed)
		if e != nil {
			return out, e
		}
		s.policies[issue] = q.K
		if err := s.persistState(); err != nil {
			return out, fmt.Errorf("persist signing policy: %w", err)
		}
		out.Signature = base64.StdEncoding.EncodeToString(enc)
		return out, nil
	}
	enc, e := decodeB64(q.Signature)
	if e != nil {
		return out, e
	}
	signed, e := UnmarshalSigned(enc)
	if e != nil {
		return out, e
	}
	if q.Op == "verify" {
		encDigest := sha256.Sum256(enc)
		if s.seen[encDigest] {
			return out, errors.New("signature replay already consumed")
		}
		e = s.verifier.Verify(ctx, msg, signed)
		out.Verified = e == nil
		if e == nil {
			s.seen[encDigest] = true
			if persistErr := s.persistState(); persistErr != nil {
				return out, fmt.Errorf("persist replay state: %w", persistErr)
			}
		}
		return out, e
	}
	if q.Op == "link" || q.Op == "trace" {
		enc2, e := decodeB64(q.SecondSignature)
		if e != nil {
			return out, e
		}
		other, e := UnmarshalSigned(enc2)
		if e != nil {
			return out, e
		}
		msg2, e := decodeB64(q.SecondMessage)
		if e != nil {
			return out, e
		}
		if q.Op == "link" {
			out.Linked, e = s.verifier.Link(ctx, msg, signed, ctx, msg2, other)
			return out, e
		}
		regs := make([]Registration, 0, len(s.accounts))
		for _, reg := range s.accounts {
			regs = append(regs, reg)
		}
		registry, e := NewRegistry(regs)
		if e != nil {
			return out, e
		}
		result, e := s.verifier.Trace(ctx, msg, signed, ctx, msg2, other, registry)
		out.Trace = result.Status
		out.User = result.UserID
		return out, e
	}
	return out, fmt.Errorf("unknown operation %q", q.Op)
}

// The local service pins k on first signing for an issue. A subsequent request
// cannot evade a consumed counter by increasing k for the same issue.
func (s *Service) policy(issue [32]byte, k uint32, create bool) error {
	if k == 0 {
		return errors.New("zero quota")
	}
	old, ok := s.policies[issue]
	if ok {
		if old != k {
			return errors.New("quota already pinned for issue")
		}
		return nil
	}
	if !create {
		return errors.New("unknown issue policy")
	}
	// A successful sign commits the new policy; validation alone is read-only.
	return nil
}

// LoadSetup initializes the service from already generated artifacts. It never
// performs a new setup, and does not restore signing keys, accounts or counters.
func (s *Service) LoadSetup(dir string, pin [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prover != nil {
		return errors.New("setup already completed")
	}
	loaded, err := LoadSetup(dir, pin)
	if err != nil {
		return err
	}
	s.params, s.prover, s.verifier = loaded.Parameters, loaded.Prover, loaded.Verifier
	return nil
}
