package nativeproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	secfr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

// Known tau is test-only: it independently checks public-polynomial evaluation.
func fixtureParams(t *testing.T, n int) Params {
	t.Helper()
	_, _, g, h := bn254.Generators()
	p := Params{G: g, H: h, Powers: make([]bn254.G1Affine, n+1)}
	tau := big.NewInt(7)
	p.HTau.ScalarMultiplication(&h, tau)
	pow := big.NewInt(1)
	for i := range p.Powers {
		p.Powers[i].ScalarMultiplication(&g, pow)
		pow.Mul(pow, tau).Mod(pow, bnfr.Modulus())
	}
	return p
}
func fixtureAccount(t *testing.T, x, d int64) Account {
	t.Helper()
	a, err := NewAccount(big.NewInt(x), big.NewInt(d))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func fixtureRing(t *testing.T) []Account {
	return []Account{fixtureAccount(t, 3, 11), fixtureAccount(t, 3, 13), fixtureAccount(t, 5, 17), fixtureAccount(t, 7, 19)}
}
func rawReduce(data []byte, mod *big.Int) *big.Int {
	d := sha256.Sum256(data)
	return new(big.Int).Mod(new(big.Int).SetBytes(d[:]), mod)
}
func arrayIssue(b byte) (out [32]byte) {
	for i := range out {
		out[i] = b + byte(i)
	}
	return
}

func TestHostSetupAndPublicPolynomial(t *testing.T) {
	randomP, err := Setup(4)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateParams(randomP); err != nil {
		t.Fatal(err)
	}
	if len(randomP.Powers) != 5 {
		t.Fatal("wrong SRS capacity")
	}
	other, err := Setup(4)
	if err != nil {
		t.Fatal(err)
	}
	if randomP.HTau.Equal(&other.HTau) {
		t.Fatal("independent CSPRNG setups repeated")
	}
	p := fixtureParams(t, 4)
	accounts := fixtureRing(t)
	v, err := Accumulate(p, accounts)
	if err != nil {
		t.Fatal(err)
	}
	product := big.NewInt(1)
	for _, a := range accounts {
		m, err := Member(a)
		if err != nil {
			t.Fatal(err)
		}
		product.Mul(product, new(big.Int).Add(m, big.NewInt(7))).Mod(product, bnfr.Modulus())
	}
	var expected bn254.G1Affine
	expected.ScalarMultiplication(&p.G, product)
	if !v.Equal(&expected) {
		t.Fatal("public polynomial differs from trapdoor evaluation")
	}
	for i, a := range accounts {
		w, err := MembershipWitness(p, accounts, i)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := Member(a)
		if !VerifyMembership(p, v, w, m) {
			t.Fatalf("member %d failed", i)
		}
		var altered bn254.G1Affine
		altered.ScalarMultiplication(&v, big.NewInt(2))
		if VerifyMembership(p, altered, w, m) {
			t.Fatal("altered accumulator accepted")
		}
	}
	outsider, _ := Member(fixtureAccount(t, 29, 31))
	inverse := new(big.Int).ModInverse(outsider, bnfr.Modulus())
	var forged bn254.G1Affine
	forged.ScalarMultiplication(&v, inverse)
	if VerifyMembership(p, v, forged, outsider) {
		t.Fatal("trapdoor-zero forgery accepted")
	}
	if VerifyMembership(p, bn254.G1Affine{}, forged, outsider) {
		t.Fatal("identity accumulator accepted")
	}
	if VerifyMembership(p, v, bn254.G1Affine{}, outsider) {
		t.Fatal("identity witness accepted")
	}
	if VerifyMembership(p, v, forged, big.NewInt(0)) {
		t.Fatal("zero member accepted")
	}
	bad := cloneParams(p)
	bad.Powers[2] = bad.Powers[1]
	if ValidateParams(bad) == nil {
		t.Fatal("inconsistent powers accepted")
	}
	if _, err = Accumulate(bad, accounts); err == nil {
		t.Fatal("bad SRS accepted by accumulator")
	}
	if _, err = Setup(0); err == nil {
		t.Fatal("zero capacity accepted")
	}
	if _, err = Setup(-1); err == nil {
		t.Fatal("negative capacity accepted")
	}
}

func TestHostHashesAndCanonicalAccounts(t *testing.T) {
	x, d := big.NewInt(3), big.NewInt(11)
	a := fixtureAccount(t, 3, 11)
	issue := arrayIssue(0x20)
	s, tt, err := Seeds(x, issue)
	if err != nil {
		t.Fatal(err)
	}
	seedData := make([]byte, 65)
	x.FillBytes(seedData[:32])
	copy(seedData[32:64], issue[:])
	if s.Cmp(rawReduce(seedData, secfr.Modulus())) != 0 {
		t.Fatal("s preimage mismatch")
	}
	seedData[64] = 1
	if tt.Cmp(rawReduce(seedData, secfr.Modulus())) != 0 {
		t.Fatal("t preimage mismatch")
	}
	if s.Cmp(tt) == 0 {
		t.Fatal("seed domains collapsed")
	}
	membersPreimage := []byte("lktrs/member/v1")
	for _, point := range []secp256k1.G1Affine{a.U, a.Y} {
		xb, yb := point.X.Bytes(), point.Y.Bytes()
		membersPreimage = append(membersPreimage, xb[:]...)
		membersPreimage = append(membersPreimage, yb[:]...)
	}
	member, err := Member(a)
	if err != nil {
		t.Fatal(err)
	}
	if member.Cmp(rawReduce(membersPreimage, bnfr.Modulus())) != 0 {
		t.Fatal("member encoding/domain mismatch")
	}
	if len(EncodeSecpPoint(a.U)) != 64 {
		t.Fatal("wrong secp encoding length")
	}
	_, _, g, _ := bn254.Generators()
	gb := EncodeBNPoint(g)
	if len(gb) != 64 || gb[31] != 1 || gb[63] != 2 {
		t.Fatal("BN generator encoding should be x=1,y=2 as 32-byte big-endian coordinates")
	}
	ring := fixtureRing(t)
	ringHash, err := RingDigest(ring)
	if err != nil {
		t.Fatal(err)
	}
	ringPreimage := []byte("lktrs/ring/v1")
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], 4)
	ringPreimage = append(ringPreimage, count[:]...)
	for _, a := range ring {
		ringPreimage = append(ringPreimage, EncodeSecpPoint(a.U)...)
		ringPreimage = append(ringPreimage, EncodeSecpPoint(a.Y)...)
	}
	if ringHash != sha256.Sum256(ringPreimage) {
		t.Fatal("ring preimage mismatch")
	}
	ring[0], ring[1] = ring[1], ring[0]
	swapped, _ := RingDigest(ring)
	if swapped == ringHash {
		t.Fatal("ring order unbound")
	}
	optional := a
	optional.D = nil
	withoutD, err := Member(optional)
	if err != nil || withoutD.Cmp(member) != 0 {
		t.Fatal("optional metadata changed member")
	}
	optional.D = big.NewInt(12)
	if _, err = Member(optional); err == nil {
		t.Fatal("inconsistent account d accepted")
	}
	changed := a
	changed.Y.X.Add(&changed.Y.X, &changed.Y.X)
	if _, err = Member(changed); err == nil {
		t.Fatal("off-curve account accepted")
	}
	changed = a
	changed.U = secp256k1.G1Affine{}
	if _, err = Member(changed); err == nil {
		t.Fatal("identity account accepted")
	}
	if _, err = NewAccount(big.NewInt(0), d); err == nil {
		t.Fatal("zero x accepted")
	}
	if _, err = NewAccount(x, big.NewInt(0)); err == nil {
		t.Fatal("zero d accepted")
	}
	if _, err = NewAccount(secfr.Modulus(), d); err == nil {
		t.Fatal("unreduced x accepted")
	}
	if _, err = NewAccount(x, secfr.Modulus()); err == nil {
		t.Fatal("unreduced d accepted")
	}
	if _, _, err = Seeds(secfr.Modulus(), issue); err == nil {
		t.Fatal("unreduced seed preimage accepted")
	}
	if _, err = RingDigest([]Account{a, a}); err == nil {
		t.Fatal("duplicate member accepted")
	}
	hash := sha256.Sum256([]byte("zero-reduction"))
	mod := new(big.Int).SetBytes(hash[:])
	if _, err = HashScalar([]byte("zero-reduction"), mod); err == nil {
		t.Fatal("zero hash scalar accepted")
	}
	generated, reused, err := KeyGen(x)
	if err != nil {
		t.Fatal(err)
	}
	if reused.Cmp(x) != 0 {
		t.Fatal("KeyGen did not reuse x")
	}
	generated.D.SetInt64(0)
	if x.Int64() != 3 || reused.Int64() != 3 {
		t.Fatal("returned metadata aliases x")
	}
}

func TestHostStatementAndChallenge(t *testing.T) {
	p, accounts := fixtureParams(t, 4), fixtureRing(t)
	issue := arrayIssue(0x40)
	message := sha256.Sum256([]byte("first message"))
	x, d := big.NewInt(3), big.NewInt(11)
	st, w, err := MakeStatement(p, accounts, 0, x, d, issue, message, 0x1020304050607080, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Member(accounts[0])
	if !VerifyMembership(p, st.V, w.W, a) {
		t.Fatal("statement membership failed")
	}
	s, tt, _ := Seeds(x, issue)
	ut, _ := IssueBase(issue)
	offset := big.NewInt(3)
	ds := new(big.Int).Add(s, offset)
	ds.Mod(ds, secfr.Modulus())
	var recoverU secp256k1.G1Affine
	recoverU.ScalarMultiplication(&st.S, ds)
	if !recoverU.Equal(&ut) {
		t.Fatal("S denominator relation failed")
	}
	_, u := secp256k1.Generators()
	var ux, negUX, tag, tagScaled, expectedR secp256k1.G1Affine
	ux.ScalarMultiplication(&u, x)
	negUX.Neg(&ux)
	tag.Add(&st.T, &negUX)
	dt := new(big.Int).Add(tt, offset)
	dt.Mod(dt, secfr.Modulus())
	tagScaled.ScalarMultiplication(&tag, dt)
	expectedR.ScalarMultiplication(&ut, st.R)
	if !tagScaled.Equal(&expectedR) {
		t.Fatal("T relation failed")
	}
	bases, _ := Bases()
	var nym bn254.G1Affine
	nym.SetInfinity()
	for i, seed := range []*big.Int{s, tt, x} {
		residue := new(big.Int).Mod(seed, bnfr.Modulus())
		var term, next bn254.G1Affine
		term.ScalarMultiplication(&bases[i], residue)
		next.Add(&nym, &term)
		nym = next
	}
	if !nym.Equal(&st.Nym) {
		t.Fatal("nym scalar-domain reduction/order failed")
	}
	preimage := []byte("lktrs/challenge/v1")
	preimage = append(preimage, st.Issue[:]...)
	preimage = append(preimage, st.RingDigest[:]...)
	preimage = append(preimage, st.MessageDigest[:]...)
	preimage = append(preimage, EncodeBNPoint(st.Nym)...)
	var tail [12]byte
	binary.BigEndian.PutUint64(tail[:8], st.Timestamp)
	binary.BigEndian.PutUint32(tail[8:], st.K)
	preimage = append(preimage, tail[:]...)
	if st.R.Cmp(rawReduce(preimage, secfr.Modulus())) != 0 {
		t.Fatal("challenge encoding mismatch")
	}
	mutations := []func(*Statement){func(q *Statement) { q.Issue[0] ^= 1 }, func(q *Statement) { q.RingDigest[0] ^= 1 }, func(q *Statement) { q.MessageDigest[0] ^= 1 }, func(q *Statement) { var n bn254.G1Affine; n.ScalarMultiplication(&q.Nym, big.NewInt(2)); q.Nym = n }, func(q *Statement) { q.Timestamp++ }, func(q *Statement) { q.K++ }}
	for i, mutate := range mutations {
		q := st
		mutate(&q)
		r, err := Challenge(q)
		if err != nil {
			t.Fatal(err)
		}
		if r.Cmp(st.R) == 0 {
			t.Fatalf("challenge field %d unbound", i)
		}
	}
	// Mutating caller secrets must not corrupt the returned witness.
	x.SetInt64(999)
	d.SetInt64(999)
	if w.X.Int64() != 3 || w.D.Int64() != 11 || w.Account.D.Int64() != 11 {
		t.Fatal("witness aliases caller secrets")
	}
	if _, _, err = MakeStatement(p, accounts, 0, big.NewInt(3), big.NewInt(11), issue, message, 1, 0, 0); err == nil {
		t.Fatal("zero k accepted")
	}
	if _, _, err = MakeStatement(p, accounts, 0, big.NewInt(3), big.NewInt(11), issue, message, 1, 8, 8); err == nil {
		t.Fatal("cnt=k accepted")
	}
	if _, _, err = MakeStatement(p, accounts, 4, big.NewInt(3), big.NewInt(11), issue, message, 1, 8, 0); err == nil {
		t.Fatal("bad selected index accepted")
	}
	if _, _, err = MakeStatement(p, accounts, 0, big.NewInt(5), big.NewInt(11), issue, message, 1, 8, 0); err == nil {
		t.Fatal("wrong user secret accepted")
	}
}

func TestHostMultiaccountAndTraceAlgebra(t *testing.T) {
	p, accounts := fixtureParams(t, 4), fixtureRing(t)
	issue := arrayIssue(0x60)
	m1 := sha256.Sum256([]byte("one"))
	m2 := sha256.Sum256([]byte("two"))
	first, _, err := MakeStatement(p, accounts, 0, big.NewInt(3), big.NewInt(11), issue, m1, 11, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := MakeStatement(p, accounts, 1, big.NewInt(3), big.NewInt(13), issue, m2, 12, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Nym.Equal(&second.Nym) || !first.S.Equal(&second.S) {
		t.Fatal("multi-account nym/S inconsistent")
	}
	if first.R.Cmp(second.R) == 0 {
		t.Fatal("test trace challenge collision")
	}
	var t1r2, t2r1, neg, quotient, recovered secp256k1.G1Affine
	t1r2.ScalarMultiplication(&first.T, second.R)
	t2r1.ScalarMultiplication(&second.T, first.R)
	neg.Neg(&t2r1)
	quotient.Add(&t1r2, &neg)
	delta := new(big.Int).Sub(second.R, first.R)
	delta.Mod(delta, secfr.Modulus())
	inv := new(big.Int).ModInverse(delta, secfr.Modulus())
	recovered.ScalarMultiplication(&quotient, inv)
	_, u := secp256k1.Generators()
	var expected secp256k1.G1Affine
	expected.ScalarMultiplication(&u, big.NewInt(3))
	if !recovered.Equal(&expected) {
		t.Fatal("trace cancellation did not recover [x]u")
	}
	traceKey, err := TraceKey(big.NewInt(3))
	if err != nil || !traceKey.Equal(&expected) {
		t.Fatal("TraceKey mismatch", err)
	}
	if _, err := TraceKey(big.NewInt(0)); err == nil {
		t.Fatal("zero trace-key secret accepted")
	}

	for _, a := range accounts[:2] {
		var y secp256k1.G1Affine
		y.ScalarMultiplication(&recovered, a.D)
		if !y.Equal(&a.Y) {
			t.Fatal("trace key failed account lookup")
		}
	}
	different, _, err := MakeStatement(p, accounts, 0, big.NewInt(3), big.NewInt(11), issue, m1, 11, 8, 3)
	if err != nil {
		t.Fatal(err)
	}
	if different.S.Equal(&first.S) {
		t.Fatal("different counters share S")
	}
	otherIssue := issue
	otherIssue[0] ^= 1
	cross, _, err := MakeStatement(p, accounts, 0, big.NewInt(3), big.NewInt(11), otherIssue, m1, 11, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	if cross.Nym.Equal(&first.Nym) || cross.S.Equal(&first.S) {
		t.Fatal("issue binding failed")
	}
}

func TestHostSnapshotAtomicityAndIsolation(t *testing.T) {
	p := fixtureParams(t, 2)
	accounts := fixtureRing(t)
	empty, err := NewSnapshot(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.value.Equal(&p.G) {
		t.Fatal("empty accumulator not G")
	}
	first, err := empty.Join(accounts[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.Join(accounts[1])
	if err != nil {
		t.Fatal(err)
	}
	before := EncodeBNPoint(second.Value())
	oldAccounts := second.Accounts()
	m0, _ := Member(accounts[0])
	m1, _ := Member(accounts[1])
	w0, err := MembershipWitness(p, second.Accounts(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = second.Join(accounts[0]); err == nil {
		t.Fatal("duplicate join accepted")
	}
	if _, err = second.Join(accounts[2]); err == nil {
		t.Fatal("over-capacity join accepted")
	}
	if _, err = second.Exit(big.NewInt(1)); err == nil {
		t.Fatal("unknown exit accepted")
	}
	if !bytes.Equal(before, EncodeBNPoint(second.Value())) || len(second.Accounts()) != 2 {
		t.Fatal("failed mutation changed snapshot")
	}
	next, err := second.Exit(m0)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyMembership(p, next.Value(), w0, m0) {
		t.Fatal("revoked witness accepted")
	}
	remaining := next.Accounts()
	if len(remaining) != 1 {
		t.Fatal("wrong exit count")
	}
	got, _ := Member(remaining[0])
	if got.Cmp(m1) != 0 {
		t.Fatal("wrong account revoked")
	}
	oldAccounts[0].D.SetInt64(0)
	p.Powers[0] = bn254.G1Affine{}
	if second.Accounts()[0].D.Sign() == 0 || second.Params().Powers[0].IsInfinity() {
		t.Fatal("snapshot shares mutable backing data")
	}
	last, err := next.Exit(m1)
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Accounts()) != 0 || !last.value.Equal(&empty.value) {
		t.Fatal("exit-to-empty failed")
	}
}

func TestHostEmptySnapshotLifecycle(t *testing.T) {
	p := fixtureParams(t, 2)
	a := fixtureAccount(t, 41, 43)
	b := fixtureAccount(t, 41, 47) // same user; both must exit to revoke the user
	initial, err := NewSnapshot(p, []Account{a, b})
	if err != nil {
		t.Fatal(err)
	}
	ma, _ := Member(a)
	mb, _ := Member(b)
	one, err := initial.Exit(ma)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := one.Exit(mb)
	if err != nil {
		t.Fatal("final-account exit failed", err)
	}
	value := empty.Value()
	if len(empty.Accounts()) != 0 || !value.Equal(&p.G) {
		t.Fatal("final exit must produce V=G")
	}
	if len(initial.Accounts()) != 2 || len(one.Accounts()) != 1 {
		t.Fatal("successful exits modified prior snapshots")
	}

	// Failed operations on the valid empty state leave its value and capacity
	// intact, and the state remains usable for an ordinary subsequent Join.
	if _, err = empty.Exit(ma); err == nil {
		t.Fatal("exit of absent member from empty state accepted")
	}
	if _, err = empty.Exit(nil); err == nil {
		t.Fatal("nil exit member accepted")
	}
	if _, err = empty.Join(Account{}); err == nil {
		t.Fatal("identity account joined empty snapshot")
	}
	afterFailures := empty.Value()
	if len(empty.Accounts()) != 0 || !afterFailures.Equal(&p.G) {
		t.Fatal("failed empty-state operation mutated snapshot")
	}
	rejoined, err := empty.Join(a)
	if err != nil {
		t.Fatal("join after final exit failed", err)
	}
	direct, err := Accumulate(p, []Account{a})
	if err != nil {
		t.Fatal(err)
	}
	rejoinedV := rejoined.Value()
	if !rejoinedV.Equal(&direct) || len(rejoined.Accounts()) != 1 {
		t.Fatal("rejoined state differs from fresh one-account state")
	}
	if len(empty.Accounts()) != 0 {
		t.Fatal("join modified empty receiver")
	}

	// Empty accumulator state is not a signature-verification context.
	if _, err = RingDigest(nil); err == nil {
		t.Fatal("empty signing ring has a digest")
	}
	issue, msg := arrayIssue(1), sha256.Sum256([]byte("empty"))
	if _, _, err = MakeStatement(p, nil, 0, big.NewInt(41), big.NewInt(43), issue, msg, 1, 3, 0); err == nil {
		t.Fatal("signed empty ring")
	}
	if _, err = MembershipWitness(p, nil, 0); err == nil {
		t.Fatal("generated an empty-ring witness")
	}

	// Parameter validation is never bypassed merely because the ring is empty.
	bad := cloneParams(p)
	bad.Powers[1] = bad.Powers[0]
	if _, err = Accumulate(bad, nil); err == nil {
		t.Fatal("empty accumulator accepted inconsistent powers")
	}
	if _, err = NewSnapshot(bad, nil); err == nil {
		t.Fatal("empty snapshot accepted inconsistent powers")
	}
	if _, err = NewSnapshot(Params{}, nil); err == nil {
		t.Fatal("empty snapshot accepted absent parameters")
	}
}

func TestHostSnapshotCopiesConstructorAndGetterInputs(t *testing.T) {
	p := fixtureParams(t, 2)
	accounts := []Account{fixtureAccount(t, 53, 59)}
	snapshot, err := NewSnapshot(p, accounts)
	if err != nil {
		t.Fatal(err)
	}
	value := snapshot.Value()
	// Mutations of both constructor inputs must not reach the owned snapshot.
	p.Powers[1] = bn254.G1Affine{}
	accounts[0].D.SetInt64(0)
	accounts[0].U = secp256k1.G1Affine{}
	if err = ValidateParams(snapshot.Params()); err != nil {
		t.Fatal("constructor SRS was retained by alias", err)
	}
	if _, err = Member(snapshot.Accounts()[0]); err != nil {
		t.Fatal("constructor account was retained by alias", err)
	}
	// Getters also return ownership-safe copies of the mutable slices/integers.
	paramsCopy := snapshot.Params()
	paramsCopy.Powers[0] = bn254.G1Affine{}
	accountCopy := snapshot.Accounts()
	accountCopy[0].D.SetInt64(0)
	if err = ValidateParams(snapshot.Params()); err != nil {
		t.Fatal("Params getter exposes owned slice", err)
	}
	if _, err = Member(snapshot.Accounts()[0]); err != nil {
		t.Fatal("Accounts getter exposes owned scalar", err)
	}
	unchanged := snapshot.Value()
	if !value.Equal(&unchanged) {
		t.Fatal("input mutations changed snapshot value")
	}
}
