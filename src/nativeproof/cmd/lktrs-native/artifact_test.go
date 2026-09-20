package main

import (
	"bytes"
	"testing"
)

func TestArtifactArgumentsFailClosed(t *testing.T) {
	for _, args := range [][]string{
		{}, {"unknown"}, {"setup"}, {"setup", "--capacity", "-1", "--out", t.TempDir() + "/invalid"},
		{"verify", "--setup", "missing"}, {"verify", "--out", "ignored"},
		{"sample", "--setup", "missing", "--manifest-sha256", "not-a-pin", "--out", "unused"},
		{"setup", "--out", t.TempDir()},
	} {
		var out, errOut bytes.Buffer
		if e := artifactCommand(args, &out, &errOut); e == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
		if out.Len() != 0 {
			t.Fatalf("failed operation emitted success: %v", args)
		}
	}
}

func TestAuthorizedVerifyArguments(t *testing.T) {
	for _, args := range [][]string{
		{"verify-authorized"},
		{"verify-authorized", "--context", "untrusted.json"},
		{"verify-authorized", "--manifest-sha256", "00"},
		{"verify-authorized", "--setup", "missing", "--policy", "missing", "--setup-approval", "missing", "--registry", "missing", "--message", "missing", "--signature", "missing"},
	} {
		var out, errOut bytes.Buffer
		if e := artifactCommand(args, &out, &errOut); e == nil || out.Len() != 0 {
			t.Fatal("unauthorized verification did not fail closed", args, e)
		}
	}
}
