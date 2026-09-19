package nativeproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceParsingAndPolicy(t *testing.T) {
	s := NewService()
	var result Response
	for _, raw := range []string{`{"op":"info"} trailing`, `{"op":"info"}{"op":"info"}`, `{"op":"info","unknown":1}`} {
		if err := json.Unmarshal(s.Handle([]byte(raw)), &result); err != nil {
			t.Fatal(err)
		}
		if result.OK {
			t.Fatalf("malformed request accepted: %s", raw)
		}
	}
	var issue [32]byte
	if s.policy(issue, 3, false) == nil {
		t.Fatal("unknown policy accepted")
	}
	if e := s.policy(issue, 3, true); e != nil {
		t.Fatal(e)
	}
	if len(s.policies) != 0 {
		t.Fatal("failed/request-only signing pinned quota")
	}
	s.policies[issue] = 3
	if s.policy(issue, 4, true) == nil {
		t.Fatal("quota reset accepted")
	}
	if e := s.policy(issue, 3, false); e != nil {
		t.Fatal(e)
	}
	if s.policy(issue, 0, true) == nil {
		t.Fatal("zero quota accepted")
	}
	if _, e := decodeIssue("00"); e == nil {
		t.Fatal("short issue")
	}
	if _, e := decodeB64("YQ==\n"); e == nil {
		t.Fatal("noncanonical base64")
	}
}

func TestPersistentServiceLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	var issue [32]byte
	issue[0] = 7
	if err := first.policy(issue, 3, true); err != nil {
		t.Fatal(err)
	}
	first.policies[issue] = 3
	first.revoked["alice"] = true
	first.seen[[32]byte{1, 2, 3}] = true
	if err := first.persistState(); err != nil {
		t.Fatal(err)
	}
	second, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.policies[issue] != 3 || !second.revoked["alice"] || !second.seen[[32]byte{1, 2, 3}] {
		t.Fatal("persistent policy, revocation or replay state was not restored")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("state file permissions are not private: %v", err)
	}
}
