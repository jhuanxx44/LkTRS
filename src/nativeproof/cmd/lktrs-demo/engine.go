package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	np "lktrs/nativeproof"
)

type config struct{ root, setup, pin, cli string }
type member struct {
	user, device string
	account      np.Account
	x            *big.Int
	key          []byte
	id           [32]byte
	wallet       string
}
type signedReport struct {
	view     reportView
	signed   np.Signed
	context  np.VerificationContext
	policy   np.TrustPolicy
	registry []byte
}
type engine struct {
	config                  config
	loaded                  *np.LoadedSetup
	runDir, publicDir       string
	pin, issue              [32]byte
	members                 []member
	ring                    np.Snapshot
	registry                np.Registry
	policy                  np.TrustPolicy
	authorization           np.RegistryAuthorization
	authority               ed25519.PrivateKey
	approval, registryBytes []byte
	authorized              *np.AuthorizedVerifier
	reports                 []signedReport
	checks                  []check
	aliceUsed, bobUsed      uint32
	revoked                 bool
	bundle                  []byte
}

func hex32(b [32]byte) string { return hex.EncodeToString(b[:]) }
func (e *engine) clearSecrets() {
	clear(e.authority)
	for _, m := range e.members {
		if m.x != nil {
			m.x.SetInt64(0)
		}
		clear(m.key)
	}
}
func (e *engine) snapshot() view {
	v := view{Epoch: e.policy.RegistryEpoch, AliceUsed: e.aliceUsed, BobUsed: e.bobUsed, Revoked: e.revoked, Checks: append([]check{}, e.checks...), Export: len(e.bundle) > 0}
	if e.runDir != "" {
		v.Run = filepath.Base(e.runDir)
		v.Issue = hex32(e.issue)
		v.Pin = hex32(e.pin)
	}
	for _, r := range e.reports {
		v.Reports = append(v.Reports, r.view)
	}
	return v
}
func (e *engine) record(label, result, detail string, start time.Time) {
	e.checks = append(e.checks, check{label, result, detail, time.Since(start).Milliseconds()})
}
func (e *engine) step(n int, progress func(string)) error {
	switch n {
	case 0:
		return e.prepare(progress)
	case 1:
		progress("Alice · 上游设备正在生成证明")
		return e.submit(0, 22.4, false)
	case 2:
		progress("重开 Alice 钱包，换用河口设备")
		if err := e.submit(1, 22.8, false); err != nil {
			return err
		}
		return e.compare(0, 1, true)
	case 3:
		progress("Bob · 支流设备正在生成证明")
		if err := e.submit(2, 21.6, false); err != nil {
			return err
		}
		return e.compare(0, 2, false)
	case 4:
		return e.exhaust(progress)
	case 5:
		progress("攻击演示：绕过钱包，重用计数槽 0")
		if err := e.submit(1, 29.7, true); err != nil {
			return err
		}
		return e.traceReuse()
	case 6:
		return e.revoke(progress)
	case 7:
		return e.exportAndVerify(progress)
	default:
		return errors.New("unknown scenario step")
	}
}

func (e *engine) load(progress func(string)) error {
	if e.loaded != nil {
		return nil
	}
	dir, pin := e.config.setup, e.config.pin
	if dir == "" {
		dir = filepath.Join(e.config.root, "setup")
		pinPath := filepath.Join(e.config.root, "setup-pin.txt")
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			progress("首次生成本地单方 setup；需要数分钟和数 GB 内存")
			params, err := np.Setup(4)
			if err != nil {
				return err
			}
			p, v, err := np.NewBackend()
			if err != nil {
				return err
			}
			digest, err := np.ExportSetup(dir, params, p, v)
			if err != nil {
				return err
			}
			if err = os.WriteFile(pinPath, []byte(hex32(digest)+"\n"), 0600); err != nil {
				return err
			}
			e.loaded = &np.LoadedSetup{Parameters: params, Prover: p, Verifier: v}
			e.pin = digest
			return nil
		} else if err != nil {
			return err
		}
		raw, err := np.ReadBoundedFile(pinPath, 128)
		if err != nil {
			return fmt.Errorf("read recorded local setup pin (do not silently regenerate): %w", err)
		}
		pin = strings.TrimSpace(string(raw))
	}
	progress("加载并校验已有 setup 的摘要和电路")
	digest, err := np.ParseDigest(pin)
	if err != nil {
		return err
	}
	loaded, err := np.LoadSetup(dir, digest)
	if err != nil {
		return err
	}
	if len(loaded.Parameters.Powers) < 5 {
		return errors.New("demo needs setup capacity >= 4")
	}
	e.loaded = loaded
	e.pin = digest
	return nil
}

func (e *engine) prepare(progress func(string)) error {
	start := time.Now()
	if err := e.load(progress); err != nil {
		return err
	}
	// The cached object survives a scenario reset; the independently recorded pin
	// is re-read rather than inferred from a candidate bundle.
	dir := e.config.setup
	if dir == "" {
		dir = filepath.Join(e.config.root, "setup")
	}
	if e.pin == ([32]byte{}) {
		pin := e.config.pin
		if pin == "" {
			b, err := np.ReadBoundedFile(filepath.Join(e.config.root, "setup-pin.txt"), 128)
			if err != nil {
				return err
			}
			pin = strings.TrimSpace(string(b))
		}
		var err error
		e.pin, err = np.ParseDigest(pin)
		if err != nil {
			return err
		}
	}
	progress("创建本次演示的成员、签名授权与加密钱包")
	var err error
	e.runDir, err = os.MkdirTemp(e.config.root, "run-")
	if err != nil {
		return err
	}
	e.publicDir = filepath.Join(e.runDir, "public-setup")
	if err = np.ExportPublicSetup(dir, e.publicDir, e.pin); err != nil {
		return err
	}
	if _, err = rand.Read(e.issue[:]); err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	e.authority = key
	now := time.Now().Unix()
	e.policy = np.TrustPolicy{Format: "lktrs/trust-policy/v1", Namespace: "sensor-cooperative", ManifestSHA256: hex32(e.pin), SetupAuthority: base64.StdEncoding.EncodeToString(pub), RegistryAuthority: base64.StdEncoding.EncodeToString(pub), RegistryEpoch: 1, Issue: hex32(e.issue), K: 3}
	e.approval, err = np.SignSetupApproval(e.pin, e.policy.Namespace, now-30, now+86400, key)
	if err != nil {
		return err
	}
	e.authorization = np.RegistryAuthorization{Format: "lktrs/registry-authorization/v1", Namespace: e.policy.Namespace, ManifestSHA256: hex32(e.pin), Epoch: 1, NotBefore: now - 30, NotAfter: now + 86400, Issue: hex32(e.issue), K: 3}
	var accounts []np.Account
	var registrations []np.Registration
	for i, identity := range [][2]string{{"alice", "upstream"}, {"alice", "estuary"}, {"bob", "tributary"}, {"carol", "reservoir"}} {
		m := member{user: identity[0], device: identity[1]}
		var shared *big.Int
		if i == 1 {
			shared = e.members[0].x
		}
		m.account, m.x, err = np.KeyGen(shared)
		if err != nil {
			return err
		}
		if i == 1 {
			m.key = e.members[0].key
			m.id = e.members[0].id
			m.wallet = e.members[0].wallet
		} else {
			m.key = make([]byte, 32)
			if _, err = rand.Read(m.key); err != nil {
				return err
			}
			if _, err = rand.Read(m.id[:]); err != nil {
				return err
			}
			m.wallet = filepath.Join(e.runDir, m.user+".vault")
			vault, err := np.CreateSignerVault(m.wallet, m.key, m.id, m.x)
			if err != nil {
				return err
			}
			vault.Close()
		}
		e.members = append(e.members, m)
		var challenge [32]byte
		if _, err = rand.Read(challenge[:]); err != nil {
			return err
		}
		enrollment, err := np.CreateEnrollment(m.x, m.account, m.user, m.device, e.policy.Namespace, e.pin, pub, challenge)
		if err != nil {
			return err
		}
		registration, err := np.VerifyEnrollment(enrollment, e.policy.Namespace, e.pin, pub, challenge)
		if err != nil {
			return err
		}
		accounts = append(accounts, m.account)
		registrations = append(registrations, registration)
		e.authorization.Entries = append(e.authorization.Entries, enrollment)
	}
	e.ring, err = np.NewSnapshot(e.loaded.Parameters, accounts)
	if err != nil {
		return err
	}
	e.registry, err = np.NewRegistry(registrations)
	if err != nil {
		return err
	}
	if err = e.authorize(); err != nil {
		return err
	}
	e.record("成员准入", "pass", "3 位演示成员 / 4 个账号；Alice 的两台设备共用一个钱包。身份标签由本地演示指定。", start)
	return nil
}
func (e *engine) authorize() error {
	var err error
	e.registryBytes, err = np.SignRegistryAuthorization(e.authorization, e.authority)
	if err != nil {
		return err
	}
	e.authorized, err = np.LoadAuthorizedVerifier(e.publicDir, e.policy, e.approval, time.Now().Unix())
	return err
}

func (e *engine) submit(memberIndex int, temperature float64, malicious bool) error {
	m := e.members[memberIndex]
	accounts := e.ring.Accounts()
	selected := -1
	for i, a := range accounts {
		if a.U.Equal(&m.account.U) && a.Y.Equal(&m.account.Y) {
			selected = i
			break
		}
	}
	if selected < 0 {
		return errors.New("device is no longer enrolled")
	}
	// No account label or precise location is placed in the public report.
	message, err := json.Marshal(struct {
		Schema      string  `json:"schema"`
		Report      int     `json:"report"`
		Project     string  `json:"project"`
		Synthetic   bool    `json:"synthetic"`
		Temperature float64 `json:"water_temperature_c"`
	}{"watershed-reading/v1", len(e.reports) + 1, "watershed-cooperative", true, temperature})
	if err != nil {
		return err
	}
	start := time.Now()
	var sig np.Signed
	if malicious {
		st, witness, err := np.MakeStatement(e.loaded.Parameters, accounts, selected, m.x, m.account.D, e.issue, sha256.Sum256(message), uint64(time.Now().Unix()), 3, 0)
		if err != nil {
			return err
		}
		sig, err = e.loaded.Prover.Prove(e.loaded.Parameters, st, witness)
		if err != nil {
			return err
		}
	} else {
		vault, err := np.OpenSignerVault(m.wallet, m.key, m.id)
		if err != nil {
			return err
		}
		defer vault.Close()
		sig, err = vault.Sign(e.loaded.Prover, e.ring, selected, e.issue, 3, message, uint64(time.Now().Unix()))
		if err != nil {
			return err
		}
		next, err := vault.NextCounter(e.issue)
		if err != nil {
			return err
		}
		if m.user == "alice" {
			e.aliceUsed = next
		} else if m.user == "bob" {
			e.bobUsed = next
		}
	}
	proveMS := time.Since(start).Milliseconds()
	verifyStart := time.Now()
	if err = e.authorized.Verify(e.registryBytes, message, sig, time.Now().Unix()); err != nil {
		return fmt.Errorf("authorized report verification: %w", err)
	}
	verifyMS := time.Since(verifyStart).Milliseconds()
	encoded, err := np.MarshalSigned(sig)
	if err != nil {
		return err
	}
	ctx, err := np.NewVerificationContext(e.loaded.Parameters, accounts, e.issue, 3)
	if err != nil {
		return err
	}
	decision := "accepted"
	if malicious {
		decision = "pending_trace"
	}
	r := signedReport{view: reportView{ID: len(e.reports) + 1, Message: string(message), Nym: hex.EncodeToString(np.EncodeBNPoint(sig.Statement.Nym)), Serial: hex.EncodeToString(np.EncodeSecpPoint(sig.Statement.S)), Epoch: e.policy.RegistryEpoch, ProofBytes: len(encoded), ProveMS: proveMS, VerifyMS: verifyMS, Decision: decision}, signed: sig, context: ctx, policy: e.policy, registry: append([]byte{}, e.registryBytes...)}
	e.reports = append(e.reports, r)
	e.record(fmt.Sprintf("报告 %02d · 真实证明", r.view.ID), "pass", fmt.Sprintf("授权验签通过，成员版本 %d；%d 字节为完整签名信封大小。", r.view.Epoch, len(encoded)), verifyStart)
	return nil
}
func (e *engine) compare(a, b int, want bool) error {
	start := time.Now()
	x, y := e.reports[a], e.reports[b]
	linked, err := e.loaded.Verifier.Link(x.context, []byte(x.view.Message), x.signed, y.context, []byte(y.view.Message), y.signed)
	if err != nil {
		return err
	}
	if linked != want {
		return errors.New("unexpected issue-scoped link result")
	}
	if want {
		traced, err := e.authorized.Trace(e.registryBytes, []byte(x.view.Message), x.signed, []byte(y.view.Message), y.signed, time.Now().Unix())
		if err != nil {
			return err
		}
		if traced.Status != np.TraceLegal {
			return errors.New("distinct wallet counters did not classify as legal")
		}
		e.record("跨设备关联", "linked", "报告 01 / 02 的 nym 相同，S 不同；重开钱包后计数继续累加，未触发追责。", start)
	} else {
		e.record("不同成员对照", "unlinked", "报告 01 / 03 的 nym 不同，本次样本未关联；这不是匿名性证明。", start)
	}
	return nil
}
func (e *engine) exhaust(progress func(string)) error {
	progress("Alice 正在使用第三个额度")
	if err := e.submit(0, 23.1, false); err != nil {
		return err
	}
	start := time.Now()
	m := e.members[1]
	vault, err := np.OpenSignerVault(m.wallet, m.key, m.id)
	if err != nil {
		return err
	}
	defer vault.Close()
	next, err := vault.NextCounter(e.issue)
	if err != nil {
		return err
	}
	if next != 3 {
		return errors.New("expected three reserved Alice counters")
	}
	_, err = vault.Sign(e.loaded.Prover, e.ring, 1, e.issue, 3, []byte("fourth honest submission"), uint64(time.Now().Unix()))
	if err == nil || err.Error() != "wallet quota exhausted or policy changed" {
		return fmt.Errorf("expected wallet quota rejection, got %v", err)
	}
	after, err := vault.NextCounter(e.issue)
	if err != nil {
		return err
	}
	if after != next {
		return errors.New("rejected request changed quota")
	}
	e.record("第四次正常提交", "rejected", "钱包拒绝生成证明；三个槽已用尽，换设备不能获得新额度。", start)
	return nil
}
func (e *engine) traceReuse() error {
	start := time.Now()
	x := e.reports[0]
	i := len(e.reports) - 1
	y := e.reports[i]
	traced, err := e.authorized.Trace(e.registryBytes, []byte(x.view.Message), x.signed, []byte(y.view.Message), y.signed, time.Now().Unix())
	if err != nil {
		return err
	}
	if traced.Status != np.TraceTraced || traced.UserID != "alice" {
		return errors.New("duplicate-counter attack did not trace to enrolled Alice")
	}
	e.reports[i].view.Decision = "rejected_reuse"
	e.reports[i].view.TraceUser = traced.UserID
	e.record("重复额度追责", "traced", "报告 01 / 05：S 相同、R 不同，恢复公开追责密钥并由授权注册表解析到 alice。业务拒收报告 05。", start)
	return nil
}
func (e *engine) revoke(progress func(string)) error {
	progress("发布成员版本 2，移除 Alice 的全部账号")
	start := time.Now()
	oldVerifier := e.authorized
	first := e.reports[0]
	newRing, err := e.registry.RevokeUser(e.ring, "alice")
	if err != nil {
		return err
	}
	if len(newRing.Accounts()) != 2 {
		return errors.New("revocation did not remove both Alice accounts")
	}
	e.ring = newRing
	e.policy.RegistryEpoch = 2
	e.authorization.Epoch = 2
	entries := make([]np.Enrollment, 0, 2)
	for _, entry := range e.authorization.Entries {
		if entry.UserID != "alice" {
			entries = append(entries, entry)
		}
	}
	e.authorization.Entries = entries
	if err = e.authorize(); err != nil {
		return err
	}
	e.revoked = true
	if err = e.authorized.Verify(first.registry, []byte(first.view.Message), first.signed, time.Now().Unix()); err == nil {
		return errors.New("old registry authorized by current policy")
	}
	if err = e.authorized.Verify(e.registryBytes, []byte(first.view.Message), first.signed, time.Now().Unix()); err == nil {
		return errors.New("old-ring proof accepted in new ring")
	}
	if err = oldVerifier.Verify(first.registry, []byte(first.view.Message), first.signed, time.Now().Unix()); err != nil {
		return fmt.Errorf("historical verification failed: %w", err)
	}
	e.record("用户级撤销", "rejected", "Alice 的两个账号均被移除。旧成员版本不符合当前策略，旧环证明也不能用于新环；原证明仍可作为历史证据验证。", start)
	// Attempt to use Alice's secret with a surviving account, without relying on
	// a UI-level revocation flag to claim cryptographic membership enforcement.
	accounts := e.ring.Accounts()
	_, _, err = np.MakeStatement(e.loaded.Parameters, accounts, 0, e.members[0].x, accounts[0].D, e.issue, sha256.Sum256([]byte("revoked signer")), 1, 3, 0)
	if err == nil {
		return errors.New("Alice could construct an honest witness for Bob's account")
	}
	progress("Bob 正在新成员集合下重新生成证明")
	if err = e.submit(2, 21.9, false); err != nil {
		return err
	}
	e.record("撤销后的正常成员", "pass", "Bob 用剩余额度在成员版本 2 中重新签名并通过授权验签。旧环变化同样要求其他成员重新签名。", start)
	return nil
}
