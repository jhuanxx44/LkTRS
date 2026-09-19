package nativeproof

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
	"testing"
)

func fixture(t *testing.T) (Params, []Account, Statement, SecretWitness) {
	t.Helper()
	p, err := Setup(4)
	if err != nil {
		t.Fatal(err)
	}
	x := big.NewInt(73)
	d := big.NewInt(13)
	a, err := NewAccount(x, d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAccount(big.NewInt(97), big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}
	sameUser, err := NewAccount(x, big.NewInt(19))
	if err != nil {
		t.Fatal(err)
	}
	accounts := []Account{b, a, sameUser}
	issue := sha256.Sum256([]byte("issue one"))
	msg := sha256.Sum256([]byte("message one"))
	s, w, err := MakeStatement(p, accounts, 1, x, d, issue, msg, 100, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	return p, accounts, s, w
}
func TestConnectedCircuit(t *testing.T) {
	p, accounts, st, w := fixture(t)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("connected constraints=%d public=%d secret=%d", cs.GetNbConstraints(), cs.GetNbPublicVariables(), cs.GetNbSecretVariables())
	solve := func(s Statement, w SecretWitness) error {
		a, e := Assignment(p, s, w)
		if e != nil {
			return e
		}
		fw, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			return e
		}
		return cs.IsSolved(fw)
	}
	if err := solve(st, w); err != nil {
		t.Fatalf("honest witness: %v", err)
	}
	// Same user signs with another account and the next counter under one
	// public statement shape. All private hashes are recomputed in circuit.
	st2, w2, err := MakeStatement(p, accounts, 2, w.X, accounts[2].D, st.Issue, sha256.Sum256([]byte("message two")), 101, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = solve(st2, w2); err != nil {
		t.Fatal(err)
	}
	if !st.Nym.Equal(&st2.Nym) || st.S.Equal(&st2.S) {
		t.Fatal("shared-user tag/counter semantics")
	}
	// All branches below use the same compiled R1CS. No host validation is
	// called in solve: malformed private relations must fail inside the CS.
	t.Run("message", func(t *testing.T) {
		bad := st
		bad.MessageDigest[0] ^= 1
		if solve(bad, w) == nil {
			t.Fatal("unbound message")
		}
	})
	t.Run("issue", func(t *testing.T) {
		bad := st
		bad.Issue[0] ^= 1
		if solve(bad, w) == nil {
			t.Fatal("unbound issue")
		}
	})
	t.Run("timestamp", func(t *testing.T) {
		bad := st
		bad.Timestamp++
		if solve(bad, w) == nil {
			t.Fatal("unbound timestamp")
		}
	})
	t.Run("ring", func(t *testing.T) {
		bad := st
		bad.RingDigest[0] ^= 1
		if solve(bad, w) == nil {
			t.Fatal("unbound ring digest")
		}
	})
	t.Run("tag", func(t *testing.T) {
		bad := st
		_, g := secp256k1.Generators()
		bad.T = g
		if solve(bad, w) == nil {
			t.Fatal("unbound T")
		}
	})
	t.Run("counter", func(t *testing.T) {
		bad := w
		bad.Counter = 3
		if solve(st, bad) == nil {
			t.Fatal("cnt=k accepted")
		}
	})
	t.Run("account", func(t *testing.T) {
		bad := w
		bad.Account = accounts[0]
		if solve(st, bad) == nil {
			t.Fatal("unbound account")
		}
	})
	t.Run("witness", func(t *testing.T) {
		bad := w
		bad.W.ScalarMultiplication(&w.W, big.NewInt(2))
		if solve(st, bad) == nil {
			t.Fatal("unbound membership")
		}
	})
	t.Run("repaired_challenge_tag", func(t *testing.T) {
		// Change R and repair T as well. Only the transcript->R constraint
		// can distinguish this from the unchanged valid algebraic equations.
		bad := st
		bad.R = new(big.Int).Add(st.R, big.NewInt(1))
		ut, e := IssueBase(st.Issue)
		if e != nil {
			t.Fatal(e)
		}
		_, seedT, e := Seeds(w.X, st.Issue)
		if e != nil {
			t.Fatal(e)
		}
		den := new(big.Int).Add(seedT, big.NewInt(int64(w.Counter)+1))
		inv := new(big.Int).ModInverse(den, secp256k1.ID.ScalarField())
		var delta secp256k1.G1Affine
		delta.ScalarMultiplication(&ut, inv)
		bad.T.Add(&st.T, &delta)
		if solve(bad, w) == nil {
			t.Fatal("R/T changed together escaped transcript binding")
		}
	})
	t.Run("outsider_with_valid_key", func(t *testing.T) {
		outside, err := NewAccount(w.X, big.NewInt(23))
		if err != nil {
			t.Fatal(err)
		}
		bad := w
		bad.Account = outside
		bad.D = outside.D
		// x and all signature tags remain correct; changed account carries
		// the same user's key but is not in the public accumulator.
		if solve(st, bad) == nil {
			t.Fatal("member-hash to accumulator disconnect")
		}
	})
	t.Run("noncanonical_secret", func(t *testing.T) {
		a, e := Assignment(p, st, w)
		if e != nil {
			t.Fatal(e)
		}
		alias := new(big.Int).Add(secp256k1.ID.ScalarField(), w.X)
		limbs := make([]frontend.Variable, 4)
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
		for i := 0; i < 4; i++ {
			limbs[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(alias), uint(64*i)), mask)
		}
		a.X = emulated.Element[emulated.Secp256k1Fr]{Limbs: limbs}
		fw, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if cs.IsSolved(fw) == nil {
			t.Fatal("x+order encoded as distinct hash preimage")
		}
	})
}
