package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	np "lktrs/nativeproof"
	"os"
	"path/filepath"
)

func emitJSON(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }
func artifactCommand(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected setup, export-public, sample, verify, or --stdio")
	}
	op := args[0]
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("setup", "", "setup bundle directory")
	pinText := fs.String("manifest-sha256", "", "independently trusted manifest SHA-256")
	output := fs.String("out", "", "new output directory (must not exist)")
	capacity := fs.Int("capacity", 4, "q-SDH ring capacity for setup")
	context := fs.String("context", "", "trusted public ring/issue/quota JSON")
	message := fs.String("message", "", "message file")
	signature := fs.String("signature", "", "binary signature file")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	allowed := map[string]map[string]bool{
		"setup":         {"out": true, "capacity": true},
		"export-public": {"setup": true, "manifest-sha256": true, "out": true},
		"sample":        {"setup": true, "manifest-sha256": true, "out": true},
		"verify":        {"setup": true, "manifest-sha256": true, "context": true, "message": true, "signature": true},
	}
	var flagErr error
	fs.Visit(func(f *flag.Flag) {
		if !allowed[op][f.Name] {
			flagErr = fmt.Errorf("flag --%s is not supported by %s", f.Name, op)
		}
	})
	if flagErr != nil {
		return flagErr
	}
	if op != "setup" && op != "export-public" && op != "sample" && op != "verify" {
		return fmt.Errorf("unknown command %q", op)
	}
	if op == "setup" {
		if *output == "" {
			return errors.New("--out required")
		}
		if _, e := os.Lstat(*output); !os.IsNotExist(e) {
			return errors.New("output already exists or cannot be inspected")
		}
		params, e := np.Setup(*capacity)
		if e != nil {
			return e
		}
		prover, verifier, e := np.NewBackend()
		if e != nil {
			return e
		}
		pin, e := np.ExportSetup(*output, params, prover, verifier)
		if e != nil {
			return e
		}
		return emitJSON(out, map[string]any{"manifest_sha256": hex.EncodeToString(pin[:]), "setup": *output, "setup_kind": "local-single-party"})
	}
	if *dir == "" || *pinText == "" {
		return errors.New("--setup and --manifest-sha256 required")
	}
	pin, e := np.ParseDigest(*pinText)
	if e != nil {
		return e
	}
	switch op {
	case "export-public":
		if *output == "" {
			return errors.New("--out required")
		}
		if e = np.ExportPublicSetup(*dir, *output, pin); e != nil {
			return e
		}
		return emitJSON(out, map[string]any{"manifest_sha256": *pinText, "public_setup": *output})
	case "sample":
		if *output == "" {
			return errors.New("--out required")
		}
		if _, e := os.Lstat(*output); !os.IsNotExist(e) {
			return errors.New("sample output exists or cannot be inspected")
		}
		loaded, e := np.LoadSetup(*dir, pin)
		if e != nil {
			return e
		}
		if e = writeSample(*output, loaded); e != nil {
			return e
		}
		return emitJSON(out, map[string]any{"sample": *output, "manifest_sha256": *pinText, "vk_sha256": loaded.Manifest.VerifyingKey.SHA256})
	case "verify":
		if *context == "" || *message == "" || *signature == "" {
			return errors.New("--context, --message and --signature required")
		}
		loaded, e := np.LoadPublicSetup(*dir, pin)
		if e != nil {
			return e
		}
		raw, e := np.ReadBoundedFile(*context, np.MaxPublicContextBytes)
		if e != nil {
			return e
		}
		ctx, e := np.UnmarshalVerificationContext(loaded.Parameters, raw)
		if e != nil {
			return e
		}
		msg, e := np.ReadBoundedFile(*message, limit)
		if e != nil {
			return e
		}
		enc, e := np.ReadBoundedFile(*signature, 2<<20)
		if e != nil {
			return e
		}
		sig, e := np.UnmarshalSigned(enc)
		if e != nil {
			return e
		}
		if e = loaded.Verifier.Verify(ctx, msg, sig); e != nil {
			return e
		}
		return emitJSON(out, map[string]any{"verified": true, "manifest_sha256": *pinText, "vk_sha256": loaded.Manifest.VerifyingKey.SHA256})
	}
	return errors.New("unsupported command")
}

// A fresh research fixture for the actual circuit, not a separate toy proof.
// No user scalar, account exponent, selected index, counter or witness is saved.
func writeSample(dir string, setup *np.LoadedSetup) error {
	if setup.Manifest.Capacity < 3 {
		return errors.New("sample requires setup capacity >= 3")
	}
	a, x, e := np.KeyGen(nil)
	if e != nil {
		return e
	}
	b, _, e := np.KeyGen(x)
	if e != nil {
		return e
	}
	c, _, e := np.KeyGen(nil)
	if e != nil {
		return e
	}
	accounts := []np.Account{a, b, c}
	issue := sha256.Sum256([]byte("lktrs/reproduction/issue"))
	msg := []byte("Lk-TRS setup export/load reproduction\n")
	ring, e := np.NewSnapshot(setup.Parameters, accounts)
	if e != nil {
		return e
	}
	signer, e := np.NewSigner(x)
	if e != nil {
		return e
	}
	sig, e := signer.Sign(setup.Prover, ring, 0, issue, 3, msg, 1)
	if e != nil {
		return e
	}
	ctx, e := np.NewVerificationContext(setup.Parameters, accounts, issue, 3)
	if e != nil {
		return e
	}
	if e = setup.Verifier.Verify(ctx, msg, sig); e != nil {
		return e
	}
	public, e := np.MarshalVerificationContext(ctx)
	if e != nil {
		return e
	}
	enc, e := np.MarshalSigned(sig)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(dir), 0700); e != nil {
		return e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return e
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(dir)
		}
	}()
	for _, f := range []struct {
		name string
		data []byte
	}{{"context.json", public}, {"message.bin", msg}, {"signature.bin", enc}} {
		if e = os.WriteFile(filepath.Join(dir, f.name), f.data, 0600); e != nil {
			return e
		}
	}
	done = true
	return nil
}
