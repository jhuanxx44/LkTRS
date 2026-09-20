package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A failed verifier process is not evidence that it reached the intended check.
func TestVerifierRejectsUnrelatedFailure(t *testing.T) {
	cli := filepath.Join(t.TempDir(), "verifier")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nprintf 'open tampered-message.json: no such file or directory\\n' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := runVerifier(cli, nil, messageRejection); err == nil {
		t.Fatal("unrelated file failure counted as a cryptographic rejection")
	}
}

func TestVerifierChecksExpectedDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name, script, expected string
		valid                  bool
	}{
		{"success", "printf '{\"verified\":true}\\n'", "", true},
		{"false result", "printf '{\"verified\":false}\\n'", "", false},
		{"message mismatch", "printf 'message mismatch\\n' >&2\nexit 1", messageRejection, true},
		{"wrong rejection", "printf 'message mismatch\\n' >&2\nexit 1", policyRejection, false},
		{"unexpected success", "printf '{\"verified\":true}\\n'", messageRejection, false},
		{"unexpected exit", "printf 'message mismatch\\n' >&2\nexit 2", messageRejection, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli := filepath.Join(t.TempDir(), "verifier")
			if err := os.WriteFile(cli, []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := runVerifier(cli, nil, tc.expected); (err == nil) != tc.valid {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}
