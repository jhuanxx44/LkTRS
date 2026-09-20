package nativeproof

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func TestSignerVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	id := sha256.Sum256([]byte("wallet id"))
	x := big.NewInt(1234567)
	v, e := CreateSignerVault(path, key, id, x)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(scalarHex(x))) {
		t.Fatal("plaintext wallet secret on disk")
	}
	if _, e = CreateSignerVault(path, key, id, x); e == nil {
		t.Fatal("overwrote existing wallet")
	}
	wrong := append([]byte{}, key...)
	wrong[0] ^= 1
	if _, e = OpenSignerVault(path, wrong, id); e == nil {
		t.Fatal("wrong wrapping key accepted")
	}
	other := id
	other[0] ^= 1
	if _, e = OpenSignerVault(path, key, other); e == nil {
		t.Fatal("wallet identity substitution")
	}
	changed := append([]byte{}, raw...)
	changed[len(changed)-1] ^= 1
	_ = os.WriteFile(path, changed, 0600)
	if _, e = OpenSignerVault(path, key, id); e == nil {
		t.Fatal("tampered vault accepted")
	}
	_ = os.WriteFile(path, raw, 0600)
	issue := sha256.Sum256([]byte("issue"))
	called := false
	_, e = v.reserveAndProve(issue, 3, func(secret *big.Int, count uint32) (Signed, error) {
		called = true
		if secret.Cmp(x) != 0 || count != 0 {
			t.Fatal("wrong witness/counter")
		}
		return Signed{}, errors.New("simulated prover failure")
	})
	if e == nil || !called {
		t.Fatal("failure fixture")
	}
	reopened, e := OpenSignerVault(path, key, id)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if count, e := reopened.NextCounter(issue); e != nil || count != 1 {
		t.Fatal("failed proof reused reserved counter", count, e)
	}
	_, e = reopened.reserveAndProve(issue, 4, func(*big.Int, uint32) (Signed, error) { t.Fatal("changed quota reached prover"); return Signed{}, nil })
	if e == nil {
		t.Fatal("quota change accepted")
	}
	_ = os.Chmod(path, 0644)
	if _, e = OpenSignerVault(path, key, id); e == nil {
		t.Fatal("publicly readable vault accepted")
	}
	_ = os.Chmod(path, 0600)
	reopened.Close()
	if _, e = reopened.NextCounter(issue); e == nil {
		t.Fatal("closed vault accepted")
	}
}
func TestSignerVaultConcurrentReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	id := sha256.Sum256([]byte("wallet id"))
	first, e := CreateSignerVault(path, key, id, big.NewInt(123))
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := OpenSignerVault(path, key, id)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	issue := sha256.Sum256([]byte("concurrent"))
	counts := make(chan uint32, 8)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		v := first
		if i%2 == 0 {
			v = second
		}
		go func() {
			defer wg.Done()
			_, e := v.reserveAndProve(issue, 8, func(_ *big.Int, count uint32) (Signed, error) { counts <- count; return Signed{}, nil })
			errs <- e
		}()
	}
	wg.Wait()
	close(counts)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	seen := map[uint32]bool{}
	for c := range counts {
		if seen[c] {
			t.Fatal("duplicate reserved counter")
		}
		seen[c] = true
	}
	if len(seen) != 8 {
		t.Fatal("missing slots")
	}
	if _, e = first.reserveAndProve(issue, 8, func(*big.Int, uint32) (Signed, error) {
		t.Fatal("exhausted wallet reached prover")
		return Signed{}, nil
	}); e == nil {
		t.Fatal("exhausted quota accepted")
	}
}

func TestSignerVaultProcessHelper(t *testing.T) {
	path := os.Getenv("LKTRS_VAULT_TEST_CHILD")
	if path == "" {
		t.Skip("subprocess fixture only")
	}
	// Public fixed test key, never a user's wrapping key.
	key := bytes.Repeat([]byte{1}, 32)
	id := sha256.Sum256([]byte("process-test"))
	issue := sha256.Sum256([]byte("process-issue"))
	v, e := OpenSignerVault(path, key, id)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	for i := 0; i < 2; i++ {
		_, e = v.reserveAndProve(issue, 4, func(_ *big.Int, count uint32) (Signed, error) {
			marker := filepath.Join(filepath.Dir(path), fmt.Sprintf("slot-%d", count))
			file, e := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return Signed{}, e
			}
			return Signed{}, file.Close()
		})
		if e != nil {
			t.Fatal(e)
		}
	}
}
func TestSignerVaultAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet")
	key := bytes.Repeat([]byte{1}, 32)
	id := sha256.Sum256([]byte("process-test"))
	v, e := CreateSignerVault(path, key, id, big.NewInt(321))
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	outputs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			command := exec.Command(os.Args[0], "-test.run=^TestSignerVaultProcessHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "LKTRS_VAULT_TEST_CHILD="+path)
			output, e := command.CombinedOutput()
			if e != nil {
				e = fmt.Errorf("wallet child: %w: %s", e, output)
			}
			outputs <- e
		}()
	}
	for i := 0; i < 2; i++ {
		if e := <-outputs; e != nil {
			t.Fatal(e)
		}
	}
	issue := sha256.Sum256([]byte("process-issue"))
	if n, e := v.NextCounter(issue); e != nil || n != 4 {
		t.Fatal("cross-process counters", n, e)
	}
}

// The permitted counter space across issues exceeds 2^32 writes. Random
// 96-bit nonces under one persistent key do not cover that usage envelope.
func TestSignerVaultNonceBudget(t *testing.T) {
	v, e := newSignerVault(filepath.Join(t.TempDir(), "wallet"), bytes.Repeat([]byte{2}, 32), sha256.Sum256([]byte("nonce-budget")))
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	aead, e := v.aead()
	if e != nil {
		t.Fatal(e)
	}
	if aead.NonceSize() < 24 {
		t.Fatal("random nonce space is too small for the allowed multi-issue wallet lifetime")
	}
}

func TestSignerVaultRejectsV1Format(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet")
	key := bytes.Repeat([]byte{3}, 32)
	id := sha256.Sum256([]byte("format-rejection"))
	v, e := CreateSignerVault(path, key, id, big.NewInt(456))
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if string(raw[:8]) != "LKTRSV02" {
		t.Fatal("new wallet did not use v2 format")
	}
	copy(raw[:8], "LKTRSV01")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenSignerVault(path, key, id); e == nil {
		t.Fatal("old AES-GCM format accepted as XChaCha")
	}
}
