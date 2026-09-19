"""Counterexamples to rejected designs, NOT tests of a complete Lk-TRS scheme.

The expected result is that each vulnerable model is attacked successfully.
All groups here are deliberately tiny; this is algebra regression, not crypto.
"""
import unittest

P, Q, G = 1019, 509, 4  # G generates a subgroup of prime order Q.


def div(a, b):
    return a * pow(b, -1, P) % P


class RejectedDesigns(unittest.TestCase):
    def test_a1_unbound_seeds_evade_k_one(self):
        # Every request uses cnt=0; selecting fresh unbound s avoids pass reuse.
        passes = [pow(G, pow(s + 1, -1, Q), P) for s in (11, 12, 13, 14)]
        self.assertEqual(len(set(passes)), 4)

    def test_a2_nonmember_opens_product_accumulator(self):
        members, outsider = (3, 5), 7
        self.assertNotIn(outsider, members)
        accumulator = pow(G, members[0] * members[1], P)
        witness = pow(accumulator, pow(outsider, -1, Q), P)
        # This equality also implies e(w,h^outsider)=e(V,h) by bilinearity.
        self.assertEqual(pow(witness, outsider, P), accumulator)

    def test_a3_fixed_challenge_allows_reverse_commitment(self):
        public_key = pow(G, 123, P)
        c, response = 37, 88
        commitment = div(pow(G, response, P), pow(public_key, c, P))
        # The forger computes commitment using the PUBLIC key, without using x.
        self.assertEqual(pow(G, response, P),
                         commitment * pow(public_key, c, P) % P)

    def test_a4_same_nym_guard_misses_cross_account_reuse(self):
        common_mask, account_base = pow(G, 311, P), pow(G, 13, P)
        nyms = [common_mask * pow(account_base, a, P) % P for a in (7, 19)]
        passes = [pow(G, pow(11 + 0 + 1, -1, Q), P) for _ in nyms]
        self.assertEqual(passes[0], passes[1])
        self.assertNotEqual(nyms[0], nyms[1])
        self.assertFalse(nyms[0] == nyms[1] and passes[0] == passes[1])

    def test_a5_static_account_mask_links_pairs_across_issues(self):
        base = pow(G, 13, P)
        rounds = [[pow(G, seed, P) * pow(base, a, P) % P for a in (7, 19)]
                  for seed in (311, 97)]
        self.assertNotEqual(rounds[0][0], rounds[1][0])
        self.assertEqual(div(*rounds[0]), div(*rounds[1]))

    def test_a6_public_products_test_candidate_account_triples(self):
        x, accounts = 17, (7, 19, 43)
        base, mask = pow(G, 13, P), pow(G, 311, P)
        nyms = [mask * pow(base, a, P) % P for a in accounts]
        products = tuple(a * x % Q for a in accounts)

        def matches(candidate):
            a, b, c = candidate
            return (pow(div(nyms[0], nyms[1]), (a - c) % Q, P) ==
                    pow(div(nyms[0], nyms[2]), (a - b) % Q, P))

        self.assertTrue(matches(products))
        # Not a universal uniqueness claim: this distinct candidate is rejected.
        self.assertFalse(matches(tuple(a * 29 % Q for a in (5, 31, 79))))


if __name__ == "__main__":
    unittest.main(verbosity=2)
