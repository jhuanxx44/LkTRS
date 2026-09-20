package main

import (
	"errors"
	"flag"
	"io"
	"time"

	np "lktrs/nativeproof"
)

// This path accepts only an independently provisioned trust policy and signed
// setup/registry authorization. It never falls back to the demo's plain context.
func authorizedVerifyCommand(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("verify-authorized", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("setup", "", "public setup bundle")
	policyFile := fs.String("policy", "", "independently provisioned trust policy")
	approvalFile := fs.String("setup-approval", "", "authority-signed setup approval")
	registryFile := fs.String("registry", "", "authority-signed active registry snapshot")
	messageFile := fs.String("message", "", "message file")
	signatureFile := fs.String("signature", "", "signature file")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || *dir == "" || *policyFile == "" || *approvalFile == "" || *registryFile == "" || *messageFile == "" || *signatureFile == "" {
		return errors.New("setup, policy, setup-approval, registry, message and signature required")
	}
	raw, e := np.ReadBoundedFile(*policyFile, 8192)
	if e != nil {
		return e
	}
	policy, e := np.ParseTrustPolicy(raw)
	if e != nil {
		return e
	}
	approval, e := np.ReadBoundedFile(*approvalFile, 16<<20)
	if e != nil {
		return e
	}
	verifier, e := np.LoadAuthorizedVerifier(*dir, policy, approval, time.Now().Unix())
	if e != nil {
		return e
	}
	registry, e := np.ReadBoundedFile(*registryFile, 16<<20)
	if e != nil {
		return e
	}
	msg, e := np.ReadBoundedFile(*messageFile, limit)
	if e != nil {
		return e
	}
	encoded, e := np.ReadBoundedFile(*signatureFile, 2<<20)
	if e != nil {
		return e
	}
	sig, e := np.UnmarshalSigned(encoded)
	if e != nil {
		return e
	}
	if e = verifier.Verify(registry, msg, sig, time.Now().Unix()); e != nil {
		return e
	}
	return emitJSON(out, map[string]any{"verified": true, "authorization": "setup-and-registry", "manifest_sha256": policy.ManifestSHA256, "registry_epoch": policy.RegistryEpoch})
}
