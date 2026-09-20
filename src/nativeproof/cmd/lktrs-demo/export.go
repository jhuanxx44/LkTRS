package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	np "lktrs/nativeproof"
)

//go:embed verify_export.py
var exportVerifier []byte

func (e *engine) exportFiles() (map[string][]byte, error) {
	files := map[string][]byte{"verify.py": exportVerifier, "setup-approval.json": e.approval}
	// Explicit allowlist: never walk the run directory containing encrypted
	// wallets, and never export the setup proving key or signer/authority keys.
	for _, name := range []string{"manifest.json", "parameters.bin", "vk.bin"} {
		b, err := np.ReadBoundedFile(filepath.Join(e.publicDir, name), 32<<20)
		if err != nil {
			return nil, err
		}
		files["public-setup/"+name] = b
	}
	for _, r := range e.reports {
		prefix := fmt.Sprintf("reports/%02d/", r.view.ID)
		sig, err := np.MarshalSigned(r.signed)
		if err != nil {
			return nil, err
		}
		ctx, err := np.MarshalVerificationContext(r.context)
		if err != nil {
			return nil, err
		}
		policy, err := json.MarshalIndent(r.policy, "", "  ")
		if err != nil {
			return nil, err
		}
		files[prefix+"message.json"] = []byte(r.view.Message)
		files[prefix+"signature.bin"] = sig
		files[prefix+"context.json"] = ctx
		files[prefix+"policy.json"] = policy
		files[prefix+"registry.json"] = r.registry
	}
	current, err := json.MarshalIndent(e.policy, "", "  ")
	if err != nil {
		return nil, err
	}
	files["current-policy.json"] = current
	files["current-registry.json"] = e.registryBytes
	files["tampered-message.json"] = []byte(`{"synthetic":true,"water_temperature_c":999}`)
	files["README.txt"] = []byte(`Lk-TRS sensor cooperative: public research evidence

Synthetic sensor readings; actual native Groth16 proofs. This bundle contains
public setup (no proving key), messages, signatures, expected ring contexts,
local authority endorsements and demo policies. No wallet, wrapping key, user
scalar, authority private key or circuit witness is exported.

From this extracted directory, run:
  python3 verify.py --verifier /absolute/path/to/lktrs-native

This checks all six signatures in separate processes, plus tampered-message
and wrong-current-policy rejection. Report 05 is a cryptographically valid
duplicate-counter signature that the application rejected after tracing.
A successful signature check alone does not mean business acceptance.

Policies, authority labels and setup pins in this bundle are demo fixtures.
Authenticate them independently before making any real trust decision. The
signed setup approval and registry expire 24 hours after the run was created;
verification uses the system clock. After expiry, plain stateless verification
of the historical context remains possible using the verify CLI, but does not
establish current authority or freshness. Do not change the clock to pass.

Example (historical public proof verification only):
  lktrs-native verify --setup public-setup --manifest-sha256 PIN \
    --context reports/01/context.json --message reports/01/message.json \
    --signature reports/01/signature.bin

PIN is the manifest_sha256 field in reports/01/policy.json, recorded by this
local rehearsal. Computing a hash of an arbitrary download is not authentication.
Setup is local single-party, enrollment labels are simulated, and the same
issue pseudonym remains linkable across accounts/rings. No production security,
complete anonymity, live IoT deployment or MPC ceremony is claimed.
`)
	return files, nil
}

func writeExport(root string, files map[string][]byte) error {
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	for name, data := range files {
		if !filepath.IsLocal(name) {
			return errors.New("non-local export path")
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
	}
	return nil
}
func zipExport(files map[string][]byte) ([]byte, error) {
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !filepath.IsLocal(name) {
			return nil, errors.New("non-local archive path")
		}
		entry, err := w.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err = entry.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func verifierArgs(root string, id int) []string {
	dir := filepath.Join(root, "reports", fmt.Sprintf("%02d", id))
	return []string{"verify-authorized", "--setup", filepath.Join(root, "public-setup"), "--policy", filepath.Join(dir, "policy.json"), "--setup-approval", filepath.Join(root, "setup-approval.json"), "--registry", filepath.Join(dir, "registry.json"), "--message", filepath.Join(dir, "message.json"), "--signature", filepath.Join(dir, "signature.bin")}
}
func replaceArg(args []string, flag, value string) []string {
	out := append([]string{}, args...)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == flag {
			out[i+1] = value
			return out
		}
	}
	panic("missing internal verifier flag")
}

const (
	messageRejection = "message mismatch"
	policyRejection  = "registry authority scope, epoch, policy or validity mismatch"
)

// An empty expectedRejection means success. Negative checks must reach the
// intended verifier diagnostic, not merely fail to read an artifact or start.
func runVerifier(cli string, args []string, expectedRejection string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if expectedRejection == "" {
		if err != nil {
			return fmt.Errorf("independent verifier: %w: %s", err, stderr.String())
		}
		var result struct {
			Verified bool `json:"verified"`
		}
		if err = json.Unmarshal(output, &result); err != nil || !result.Verified {
			return errors.New("independent verifier did not report verified=true")
		}
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return fmt.Errorf("expected independent verifier rejection, got %v", err)
		}
		if diagnostic := strings.TrimSpace(stderr.String()); diagnostic != expectedRejection {
			return fmt.Errorf("expected verifier rejection %q, got %q", expectedRejection, diagnostic)
		}
	}
	return nil
}
func (e *engine) exportAndVerify(progress func(string)) error {
	progress("导出公开材料，启动独立验签进程")
	files, err := e.exportFiles()
	if err != nil {
		return err
	}
	root := filepath.Join(e.runDir, "export")
	if err = writeExport(root, files); err != nil {
		return err
	}
	for _, r := range e.reports {
		progress(fmt.Sprintf("独立进程复核报告 %02d / %02d", r.view.ID, len(e.reports)))
		start := time.Now()
		if err = runVerifier(e.config.cli, verifierArgs(root, r.view.ID), ""); err != nil {
			return err
		}
		e.record(fmt.Sprintf("独立 CLI · 报告 %02d", r.view.ID), "pass", "独立进程仅加载公开 setup、策略、授权成员表、消息和签名。", start)
	}
	start := time.Now()
	args := verifierArgs(root, 1)
	if err = runVerifier(e.config.cli, replaceArg(args, "--message", filepath.Join(root, "tampered-message.json")), messageRejection); err != nil {
		return err
	}
	e.record("篡改报告温度", "rejected", "独立验签拒绝被修改的消息。", start)
	start = time.Now()
	if err = runVerifier(e.config.cli, replaceArg(args, "--policy", filepath.Join(root, "current-policy.json")), policyRejection); err != nil {
		return err
	}
	e.record("旧成员版本冒充当前版本", "rejected", "独立验签拒绝以版本 2 策略接受版本 1 授权。", start)
	state := e.snapshot()
	summary, err := json.MarshalIndent(struct {
		Format         string       `json:"format"`
		Run            string       `json:"run"`
		Issue          string       `json:"issue"`
		ManifestSHA256 string       `json:"manifest_sha256"`
		Quota          uint32       `json:"quota"`
		CurrentEpoch   uint64       `json:"current_epoch"`
		Reports        []reportView `json:"reports"`
		Checks         []check      `json:"checks"`
	}{"lktrs/demo-evidence/v1", state.Run, state.Issue, state.Pin, 3, state.Epoch, state.Reports, state.Checks}, "", "  ")
	if err != nil {
		return err
	}
	files["results.json"] = summary
	if err = os.WriteFile(filepath.Join(root, "results.json"), summary, 0600); err != nil {
		return err
	}
	bundle, err := zipExport(files)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(e.runDir, "public-evidence.zip"), bundle, 0600); err != nil {
		return err
	}
	e.bundle = bundle
	return nil
}
