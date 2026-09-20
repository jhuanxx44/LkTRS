package nativeproof

// This adapter verifies a bounded q-SDH parameter contribution chain using the
// pinned gnark Phase1 protocol. It does NOT perform Groth16 Phase1/Phase2, attest
// contributor independence, authenticate a beacon, or prove secret erasure.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
)

const maxQSDHContributions = 64
const maxQSDHTranscriptBytes = 64 << 20

func ceremonyDomain(capacity int) (uint64, error) {
	if capacity < 1 || capacity > 65536 {
		return 0, errors.New("ceremony capacity must be in [1,65536]")
	}
	n := uint64(2)
	for 2*n-1 < uint64(capacity+1) {
		n *= 2
	}
	return n, nil
}

// The pinned compressed Phase1 layout has 3*(G1+G2), uint64 N,
// G2 beta, 2N-2 G1 tau, N-1 G2 tau, N G1 beta, N G1 alpha,
// uint8 challenge length, challenge. Check every prefix before allocating N.
func decodeQSDHContribution(raw []byte, n uint64) (*mpcsetup.Phase1, error) {
	if uint64(len(raw)) != 192*n+265 {
		return nil, errors.New("invalid compressed contribution length")
	}
	pos := 0
	point := func(size int) error {
		if pos+size > len(raw) || raw[pos]&0xc0 == 0 {
			return errors.New("contribution requires compressed points")
		}
		pos += size
		return nil
	}
	for i := 0; i < 3; i++ {
		if e := point(32); e != nil {
			return nil, e
		}
		if e := point(64); e != nil {
			return nil, e
		}
	}
	if binary.BigEndian.Uint64(raw[pos:pos+8]) != n {
		return nil, errors.New("contribution domain differs from trusted capacity")
	}
	pos += 8
	if e := point(64); e != nil {
		return nil, e
	}
	for i := uint64(0); i < 2*n-2; i++ {
		if e := point(32); e != nil {
			return nil, e
		}
	}
	for i := uint64(0); i < n-1; i++ {
		if e := point(64); e != nil {
			return nil, e
		}
	}
	for i := uint64(0); i < 2*n; i++ {
		if e := point(32); e != nil {
			return nil, e
		}
	}
	if pos+33 != len(raw) || raw[pos] != 32 {
		return nil, errors.New("contribution must contain a complete predecessor challenge")
	}
	p := new(mpcsetup.Phase1)
	reader := bytes.NewReader(raw)
	if _, e := p.ReadFrom(reader); e != nil {
		return nil, e
	}
	if reader.Len() != 0 {
		return nil, errors.New("trailing contribution")
	}
	var canonical bytes.Buffer
	if _, e := p.WriteTo(&canonical); e != nil {
		return nil, e
	}
	if !bytes.Equal(raw, canonical.Bytes()) {
		return nil, errors.New("noncanonical contribution")
	}
	return p, nil
}
func checkedQSDHChain(capacity int, contributions [][]byte) (*mpcsetup.Phase1, uint64, error) {
	n, e := ceremonyDomain(capacity)
	if e != nil {
		return nil, 0, e
	}
	if len(contributions) > maxQSDHContributions {
		return nil, 0, errors.New("too many contributions")
	}
	var total int64
	for _, raw := range contributions {
		total += int64(len(raw))
	}
	if total > maxQSDHTranscriptBytes {
		return nil, 0, errors.New("oversized ceremony transcript")
	}
	previous := mpcsetup.NewPhase1(n)
	for i, raw := range contributions {
		next, e := decodeQSDHContribution(raw, n)
		if e != nil {
			return nil, 0, fmt.Errorf("contribution %d: %w", i, e)
		}
		if e = previous.Verify(next); e != nil {
			return nil, 0, fmt.Errorf("contribution %d: %w", i, e)
		}
		previous = next
	}
	return previous, n, nil
}

// ContributeQSDH checks the entire previous chain before adding fresh entropy.
// Each independent participant runs this on their own trusted machine; returned
// bytes are public. A second invocation on one machine is only a rehearsal.
func ContributeQSDH(capacity int, previous [][]byte) ([]byte, error) {
	if len(previous) >= maxQSDHContributions {
		return nil, errors.New("contribution limit reached")
	}
	n, e := ceremonyDomain(capacity)
	if e != nil {
		return nil, e
	}
	if uint64(len(previous)+1)*(192*n+265) > maxQSDHTranscriptBytes {
		return nil, errors.New("next contribution would exceed transcript budget")
	}
	state, _, e := checkedQSDHChain(capacity, previous)
	if e != nil {
		return nil, e
	}
	state.Contribute()
	var buf bytes.Buffer
	if _, e = state.WriteTo(&buf); e != nil {
		return nil, e
	}
	return buf.Bytes(), nil
}

type QSDHCeremonyReceipt struct {
	Format             string   `json:"format"`
	Gnark              string   `json:"gnark"`
	GnarkCrypto        string   `json:"gnark_crypto"`
	Capacity           int      `json:"capacity"`
	Domain             uint64   `json:"domain"`
	ContributionSHA256 []string `json:"contribution_sha256"`
	Beacon             string   `json:"beacon"`
	ParametersSHA256   string   `json:"parameters_sha256"`
}

// FinalizeQSDHCeremony reconstructs and verifies the chain and final beacon
// transformation. Two contributions are a workflow minimum, not evidence of two
// independent honest people. The caller must authenticate the ordered transcript
// and post-contribution beacon. Full transcripts expose more SRS powers than the
// truncated Params; SECURITY.md records the resulting assumption boundary.
func FinalizeQSDHCeremony(capacity int, contributions [][]byte, beacon [32]byte) (Params, QSDHCeremonyReceipt, error) {
	invalid := QSDHCeremonyReceipt{}
	if len(contributions) < 2 || beacon == ([32]byte{}) {
		return Params{}, invalid, errors.New("need at least two contributions and an externally authenticated beacon")
	}
	state, n, e := checkedQSDHChain(capacity, contributions)
	if e != nil {
		return Params{}, invalid, e
	}
	commons := state.Seal(beacon[:])
	_, _, g, h := bn254.Generators()
	params := Params{G: g, H: h, HTau: commons.G2.Tau[1], Powers: append([]bn254.G1Affine{}, commons.G1.Tau[:capacity+1]...)}
	if e = ValidateParams(params); e != nil {
		return Params{}, invalid, e
	}
	raw, e := MarshalParams(params)
	if e != nil {
		return Params{}, invalid, e
	}
	receipt := QSDHCeremonyReceipt{"lktrs/qsdh-ceremony-receipt/v1", gnarkVersion, cryptoVersion, capacity, n, make([]string, len(contributions)), hexDigest(beacon), hexDigest(sha256.Sum256(raw))}
	for i, b := range contributions {
		receipt.ContributionSHA256[i] = hexDigest(sha256.Sum256(b))
	}
	return params, receipt, nil
}
