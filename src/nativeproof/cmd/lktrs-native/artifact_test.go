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
