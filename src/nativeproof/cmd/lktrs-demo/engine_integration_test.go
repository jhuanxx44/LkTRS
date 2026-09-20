package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	np "lktrs/nativeproof"
)

// This deliberately runs the same application workflow, never a fake prover.
// Reusing setup requires an explicit pin: tests must not turn a downloaded
// manifest into an authenticated setup by hashing it themselves.
func TestDemoRealProofWorkflow(t *testing.T) {
	if os.Getenv("LKTRS_PROVE") != "1" {
		t.Skip("set LKTRS_PROVE=1 and LKTRS_DEMO_CLI for real proofs")
	}
	cli := os.Getenv("LKTRS_DEMO_CLI")
	if cli == "" {
		t.Fatal("LKTRS_DEMO_CLI must point to a separately built lktrs-native")
	}
	c := config{root: t.TempDir(), cli: cli, setup: os.Getenv("LKTRS_DEMO_SETUP"), pin: os.Getenv("LKTRS_DEMO_PIN")}
	if (c.setup == "") != (c.pin == "") {
		t.Fatal("setup and trusted pin must be supplied together")
	}
	e := &engine{config: c}
	defer e.clearSecrets()
	for step := range steps {
		start := time.Now()
		if err := e.step(step, func(phase string) { t.Log(phase) }); err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		t.Logf("step %d completed in %s", step, time.Since(start))
		switch step {
		case 0:
			if len(e.ring.Accounts()) != 4 || len(e.members) != 4 || e.members[0].wallet != e.members[1].wallet {
				t.Fatal("wrong enrollment or shared wallet")
			}
		case 1:
			if e.aliceUsed != 1 || len(e.reports) != 1 {
				t.Fatal("first submission did not consume quota")
			}
		case 2:
			if e.aliceUsed != 2 || e.reports[0].view.Nym != e.reports[1].view.Nym || e.reports[0].view.Serial == e.reports[1].view.Serial {
				t.Fatal("account switch broke link/quota")
			}
		case 3:
			if e.bobUsed != 1 || e.reports[0].view.Nym == e.reports[2].view.Nym {
				t.Fatal("cross-user fixture linked")
			}
		case 4:
			if e.aliceUsed != 3 || len(e.reports) != 4 {
				t.Fatal("wallet exceeded quota")
			}
		case 5:
			r := e.reports[4]
			if r.view.Decision != "rejected_reuse" || r.view.TraceUser != "alice" || r.view.Serial != e.reports[0].view.Serial || e.aliceUsed != 3 {
				t.Fatal("attack was not traced and rejected")
			}
			// A repeated presentation is replay, not a new attributable offence.
			x := e.reports[0]
			replayed, err := e.authorized.Trace(e.registryBytes, []byte(x.view.Message), x.signed, []byte(x.view.Message), x.signed, time.Now().Unix())
			if err != nil || replayed.Status != np.TraceReplay {
				t.Fatal("replay misclassified", err)
			}
		case 6:
			if !e.revoked || e.policy.RegistryEpoch != 2 || len(e.ring.Accounts()) != 2 || e.bobUsed != 2 || len(e.reports) != 6 {
				t.Fatal("incorrect revocation or surviving member behavior")
			}
			for _, entry := range e.authorization.Entries {
				if entry.UserID == "alice" {
					t.Fatal("revoked account still enrolled")
				}
			}
			if e.reports[2].view.Nym != e.reports[5].view.Nym {
				t.Fatal("same-issue link changed with ring")
			}
			// Actual signing attempt must fail for BOTH revoked devices.
			for _, idx := range []int{0, 1} {
				if err := e.submit(idx, 25, false); err == nil {
					t.Fatal("revoked device submitted")
				}
			}
		case 7:
			if len(e.bundle) == 0 || len(e.checks) != 21 {
				t.Fatalf("missing export/checks: %d", len(e.checks))
			}
		}
	}
	r, err := zip.NewReader(bytes.NewReader(e.bundle), int64(len(e.bundle)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 40 {
		t.Fatalf("public export inventory changed: %d files", len(r.File))
	}
	for _, f := range r.File {
		if strings.Contains(f.Name, "vault") || strings.Contains(f.Name, "pk.bin") || !filepath.IsLocal(f.Name) {
			t.Fatalf("private or unsafe export: %s", f.Name)
		}
		if f.Name == "results.json" {
			reader, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			var summary struct {
				Format       string       `json:"format"`
				CurrentEpoch uint64       `json:"current_epoch"`
				Reports      []reportView `json:"reports"`
				Checks       []check      `json:"checks"`
			}
			if err = json.Unmarshal(raw, &summary); err != nil {
				t.Fatal(err)
			}
			if summary.Format != "lktrs/demo-evidence/v1" || summary.CurrentEpoch != 2 || len(summary.Reports) != 6 || len(summary.Checks) != 21 {
				t.Fatal("incomplete exported evidence summary")
			}
			if bytes.Contains(raw, []byte(`"token"`)) || bytes.Contains(raw, []byte(`"busy"`)) {
				t.Fatal("export leaked session state")
			}
		}
	}
	state, err := json.Marshal(e.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range e.members {
		if bytes.Contains(state, []byte(m.x.String())) {
			t.Fatal("state exposed signer scalar")
		}
	}
	// Corrupted cached setup pins must fail before creating a new scenario.
	broken := &engine{config: config{root: t.TempDir(), setup: filepath.Dir(filepath.Join(e.publicDir, "manifest.json")), pin: strings.Repeat("0", 64)}}
	if err := broken.load(func(string) {}); err == nil {
		t.Fatal("untrusted setup accepted")
	}
}
