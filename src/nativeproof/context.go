package nativeproof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const MaxPublicContextBytes = 16 << 20

type publicAccountEncoding struct {
	U string `json:"u"`
	Y string `json:"y"`
}
type publicContextEncoding struct {
	Format   string                  `json:"format"`
	Issue    string                  `json:"issue"`
	K        uint32                  `json:"k"`
	Accounts []publicAccountEncoding `json:"accounts"`
}

// MarshalVerificationContext exports only the public ring, issue and quota.
// The recipient must supply this expected context independently of a signature.
// Setup points are obtained separately from the pinned setup bundle.
func MarshalVerificationContext(ctx VerificationContext) ([]byte, error) {
	out := publicContextEncoding{Format: "lktrs/context/v1", Issue: hex.EncodeToString(ctx.issue[:]), K: ctx.k, Accounts: make([]publicAccountEncoding, len(ctx.accounts))}
	for i, a := range ctx.accounts {
		out.Accounts[i] = publicAccountEncoding{hex.EncodeToString(EncodeSecpPoint(a.U)), hex.EncodeToString(EncodeSecpPoint(a.Y))}
	}
	raw, e := json.MarshalIndent(out, "", "  ")
	if e != nil {
		return nil, e
	}
	if len(raw)+1 > MaxPublicContextBytes {
		return nil, errors.New("public context exceeds size budget")
	}
	return append(raw, '\n'), nil
}
func UnmarshalVerificationContext(params Params, raw []byte) (VerificationContext, error) {
	var in publicContextEncoding
	if len(raw) > MaxPublicContextBytes {
		return VerificationContext{}, errors.New("oversized public context")
	}
	if e := strictJSON(raw, &in); e != nil {
		return VerificationContext{}, e
	}
	if in.Format != "lktrs/context/v1" || len(in.Accounts) > len(params.Powers)-1 {
		return VerificationContext{}, errors.New("invalid public context format or capacity")
	}
	issue, e := decodeIssue(in.Issue)
	if e != nil {
		return VerificationContext{}, e
	}
	accounts := make([]Account, len(in.Accounts))
	for i, entry := range in.Accounts {
		for j, s := range []string{entry.U, entry.Y} {
			b, e := hex.DecodeString(s)
			if e != nil || len(b) != 64 || hex.EncodeToString(b) != s {
				return VerificationContext{}, errors.New("noncanonical account coordinates")
			}
			point, e := readSecp(bytes.NewReader(b))
			if e != nil {
				return VerificationContext{}, e
			}
			if j == 0 {
				accounts[i].U = point
			} else {
				accounts[i].Y = point
			}
		}
	}
	return NewVerificationContext(params, accounts, issue, in.K)
}
