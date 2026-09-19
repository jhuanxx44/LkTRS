#include "lktrs/crypto/pairing.hpp"
#include "lktrs/crypto/sha256.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <cstdint>

using namespace lktrs::crypto;

static_assert(!std::is_same_v<G1, G2>);
static_assert(!std::is_constructible_v<G1, const G2&>);
static_assert(!std::is_assignable_v<G1&, G2>);
static_assert(!std::is_invocable_v<decltype(&pair), const G2&, const G1&>);
static_assert(std::is_nothrow_move_constructible_v<Scalar>);

namespace {
void require(bool condition, const char* explanation) {
    if (!condition) throw std::runtime_error(explanation);
}
template<class Error, class F>
void rejects(F&& operation) {
    try { operation(); }
    catch (const Error&) { return; }
    throw std::runtime_error("expected operation to reject");
}
PairingContext context(const std::string& parameters) {
    return PairingContext::from_trusted_parameters("resource-test-fixture", parameters);
}
template<class Group>
Group nonidentity(const PairingContext& ctx) {
    for (int i = 0; i < 32; ++i) {
        auto value = Group::sample_for_testing(ctx);
        if (!value.equals(Group(ctx))) return value;
    }
    throw std::runtime_error("could not sample a nonidentity test element");
}
template<class Group>
void group_ownership(const PairingContext& ctx) {
    auto original = nonidentity<Group>(ctx);
    const auto expected = original;
    auto copy = original;
    original = Group(ctx);
    require(copy.equals(expected), "copy aliased overwritten group element");
    require(!copy.equals(original), "nonidentity test precondition failed");
    Group assigned(ctx);
    assigned = copy;
    copy = Group(ctx);
    require(assigned.equals(expected), "copy assignment was shallow");

    auto moved = std::move(assigned);
    require(!assigned.has_value(), "move did not empty source");
    require(moved.equals(expected), "move lost group value");
    rejects<std::logic_error>([&] { (void)assigned.equals(moved); });
    rejects<std::logic_error>([&] { (void)Group(assigned); });
    assigned = moved;
    require(assigned.equals(expected), "moved-from target cannot be rebuilt");
    std::vector<Group> values;
    for (int i = 0; i < 64; ++i) values.push_back(moved);
    for (const auto& v : values) require(v.equals(expected), "vector move corrupted element");
}

std::vector<std::uint8_t> wide_encoding(std::size_t width, int fill) {
    return std::vector<std::uint8_t>(width, static_cast<std::uint8_t>(fill));
}

// Little-endian reader used only to assert the canonical encoding order.
std::uint64_t low_order_value(const std::vector<std::uint8_t>& bytes) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size() && i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[bytes.size() - 1 - i]) << (8 * i);
    }
    return value;
}

template<class Group>
void group_encoding_round_trip(const PairingContext& ctx) {
    auto element = nonidentity<Group>(ctx);
    const auto width = element.byte_length();
    const auto encoded = element.to_bytes();
    require(encoded.size() == width, "group encoding is not fixed length");
    require(Group::from_bytes(ctx, encoded).equals(element),
            "group encoding did not round trip");

    // Every nine-bit pattern (representable or not) must round trip to itself.
    // A point whose encoded x-coordinate is unrepresentable must be rejected,
    // not silently decoded to something else.
    for (int pattern = 0; pattern < 512; ++pattern) {
        std::vector<std::uint8_t> candidate = encoded;
        candidate[0] = static_cast<std::uint8_t>(pattern & 0xFF);
        candidate[1] = static_cast<std::uint8_t>((pattern >> 8) & 0x01);
        try {
            const auto decoded = Group::from_bytes(ctx, candidate);
            require(decoded.to_bytes() == candidate,
                    "accepted a group encoding that is not canonical");
        } catch (const std::invalid_argument&) {
            // Explicitly rejected: acceptable for this research encoding.
        }
    }

    // The encoding must depend on the value. The identity must encode AND decode
    // back to the identity: byte equality alone is not sufficient here, because
    // Type A's identity encoding is lossy and round-trips as bytes while turning
    // into a different group element. This is the M1 regression.
    const auto identity = Group(ctx);
    const auto encoded_identity = identity.to_bytes();
    require(!encoded_identity.empty(), "identity has no encoding");
    const auto decoded_identity = Group::from_bytes(ctx, encoded_identity);
    require(decoded_identity.equals(identity),
            "decode(encode(identity)) is not the identity group element");
    require(decoded_identity.is_identity(),
            "decode(encode(identity)) is not detected as the identity");
    const auto other = nonidentity<Group>(ctx);
    if (!other.equals(element)) {
        require(other.to_bytes() != encoded, "distinct group values share an encoding");
    }
}

void scalar_arithmetic(const PairingContext& ctx) {
    const auto three = scalar(ctx, 3);
    const auto five = scalar(ctx, 5);
    require(add(three, five).equals(scalar(ctx, 8)), "scalar addition failed");
    require(sub(five, three).equals(scalar(ctx, 2)), "scalar subtraction failed");
    require(mul(three, five).equals(scalar(ctx, 15)), "scalar multiplication failed");
    // -1 * -1 == 1 also proves signed input is reduced, not stored as a negative.
    require(scalar(ctx, -1).negate().equals(scalar(ctx, 1)), "scalar negation failed");
    require(add(three, three.negate()).is_zero(), "x + (-x) is not zero");
    require(inverse(three).mul(three).equals(scalar(ctx, 1)),
            "scalar inverse is not multiplicative");
    require(scalar(ctx, 0).is_zero(), "zero scalar not detected");
    require(!three.is_zero(), "nonzero scalar reported as zero");

    rejects<std::logic_error>([&] { (void)three.is_identity(); });
    rejects<std::logic_error>([&] { (void)three.inverse(); });
}

void scalar_encoding(const PairingContext& ctx) {
    const auto width = scalar(ctx, 1).byte_length();
    require(width == (ctx.scalar_order_bits() + 7) / 8,
            "scalar encoding width does not match the order width");
    const auto zero = scalar(ctx, 0);
    require(zero.to_bytes().size() == width, "zero scalar is not fixed length");
    require(zero.to_bytes() == wide_encoding(width, 0), "zero is not all zero bytes");
    require(Scalar::from_bytes(ctx, zero.to_bytes()).is_zero(), "zero encoding did not round trip");
    rejects<std::domain_error>([&] { (void)non_zero_scalar_from_bytes(ctx, zero.to_bytes()); });

    for (long value : {1L, 255L, 256L, -1L}) {
        const auto original = scalar(ctx, value);
        const auto encoded = original.to_bytes();
        require(encoded.size() == width, "scalar encoding is not fixed length");
        require(Scalar::from_bytes(ctx, encoded).equals(original), "scalar encoding did not round trip");
        require(non_zero_scalar_from_bytes(ctx, encoded).equals(original),
                "non-zero scalar decoding changed the value");
    }
    // The encoding is big-endian and left-padded, so small values must land in
    // the low-order (trailing) bytes and the leading bytes must stay zero.
    require(low_order_value(scalar(ctx, 256).to_bytes()) == 256,
            "scalar encoding is not a big-endian fixed-width value");
    require(low_order_value(scalar(ctx, 65536).to_bytes()) == 65536,
            "scalar encoding lost high-order value bytes");
    require(scalar(ctx, 1).to_bytes().front() == 0,
            "small scalar must be left-padded with zeros");

    rejects<std::invalid_argument>([&] { (void)Scalar::from_bytes(ctx, wide_encoding(width - 1, 0)); });
    rejects<std::invalid_argument>([&] { (void)Scalar::from_bytes(ctx, wide_encoding(width + 1, 0)); });
    // All-ones is >= any plausible scalar order, so it is not a field element.
    rejects<std::invalid_argument>([&] { (void)Scalar::from_bytes(ctx, wide_encoding(width, 0xFF)); });
    rejects<std::invalid_argument>([&] {
        (void)non_zero_scalar_from_bytes(ctx, wide_encoding(width, 0xFF));
    });
}

template<class Group>
void group_inverse_and_identity(const PairingContext& ctx) {
    auto element = nonidentity<Group>(ctx);
    require(element.mul(element.inverse()).equals(Group(ctx)),
            "group element times its inverse is not the identity");
    require(Group(ctx).is_identity(), "group identity not detected");
    require(!element.is_identity(), "nonidentity group element reported as identity");
    // The identity is its own inverse; a group inverse must accept it. Rejecting
    // it conflated the scalar field's additive identity with a group's identity
    // element and broke generic division after a legal cancellation.
    const auto identity = Group(ctx);
    require(identity.inverse().equals(identity), "the identity is not its own inverse");
    require(identity.inverse().is_identity(), "identity inverse is not the identity");
    rejects<std::logic_error>([&] { (void)element.is_zero(); });
    rejects<std::logic_error>([&] { (void)element.negate(); });
}

// SHA-256 is checked against published FIPS 180-4 vectors, then the scalar
// derivation is checked for determinism, domain separation, and the nonzero
// guarantee that makes the result usable as an invertible challenge.
void hash_derivation(const PairingContext& ctx) {
    const auto hex = [](const std::array<std::uint8_t, 32>& digest) {
        static const char* digits = "0123456789abcdef";
        std::string text;
        for (auto byte : digest) {
            text.push_back(digits[byte >> 4]);
            text.push_back(digits[byte & 0x0F]);
        }
        return text;
    };
    require(hex(sha256("")) ==
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 empty vector mismatch");
    require(hex(sha256("abc")) ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 abc vector mismatch");
    // The 56-byte input forces a second padding block; 64 bytes exercises the
    // exact-multiple-of-the-block-size boundary.
    require(hex(sha256(std::string(64, 'a'))) ==
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            "SHA-256 64-byte vector mismatch");
    require(hex(sha256(std::string(1000, 'x'))) ==
                "44f8354494a5ba03ba1792a8d3e9c534c47a9181980fde7a3f44b06ef2ae7c7f",
            "SHA-256 1000-byte vector mismatch");

    const std::vector<std::uint8_t> message{'a', 'c', 'c'};
    const auto first = Scalar::hash_to_scalar(ctx, "lktrs/test/one", message);
    require(first.equals(Scalar::hash_to_scalar(ctx, "lktrs/test/one", message)),
            "hash_to_scalar is not deterministic");
    require(!first.equals(Scalar::hash_to_scalar(ctx, "lktrs/test/two", message)),
            "hash_to_scalar ignored the domain separator");
    require(!first.equals(Scalar::hash_to_scalar(ctx, "lktrs/test/one", {'a', 'c'})),
            "hash_to_scalar ignored the message");
    require(!first.is_zero(), "hash_to_scalar produced zero");
    // The domain and message are length-prefixed, so shifting a byte between
    // them must not collide.
    require(!Scalar::hash_to_scalar(ctx, "ab", {'c'}).equals(Scalar::hash_to_scalar(ctx, "a", {'b', 'c'})),
            "hash_to_scalar encoding is not prefix-free");
    // A challenge must be invertible; this is the property the Fiat-Shamir
    // transform and the s+cnt+1 exponents rely on.
    require(first.mul(inverse(first)).equals(scalar(ctx, 1)),
            "hash_to_scalar output is not invertible");
}

void run(const std::string& params) {
    auto ctx = context(params);
    require(ctx.scalar_order_bits() > 100, "unexpected test fixture order");
    auto alias = ctx;
    require(scalar(ctx, 3).equals(scalar(alias, 3)), "copied context is not shared");

    auto five = scalar(ctx, 5);
    auto copy = five;
    five = scalar(ctx, 7);
    require(copy.equals(scalar(ctx, 5)), "scalar copy was shallow");
    copy = five;
    five = scalar(ctx, 11);
    require(copy.equals(scalar(ctx, 7)), "scalar copy assignment was shallow");
    require(copy.mul(inverse(copy)).equals(scalar(ctx, 1)), "scalar inversion failed");
    require(scalar(ctx, -1).mul(scalar(ctx, -1)).equals(scalar(ctx, 1)),
            "signed scalar reduction failed");
    rejects<std::domain_error>([&] { (void)inverse(scalar(ctx, 0)); });

    group_ownership<G1>(ctx);
    group_ownership<G2>(ctx);
    group_ownership<GT>(ctx);

    scalar_arithmetic(ctx);
    scalar_encoding(ctx);
    hash_derivation(ctx);
    group_inverse_and_identity<G1>(ctx);
    group_inverse_and_identity<G2>(ctx);
    group_inverse_and_identity<GT>(ctx);
    group_encoding_round_trip<G1>(ctx);
    group_encoding_round_trip<G2>(ctx);
    group_encoding_round_trip<GT>(ctx);

    auto g = nonidentity<G1>(ctx);
    auto h = nonidentity<G2>(ctx);
    const auto g_before = g;
    const auto h_before = h;
    const auto a = scalar(ctx, 3);
    const auto b = scalar(ctx, 7);
    const auto e = pair(g, h);
    require(!e.equals(GT(ctx)), "pairing test used degenerate input");
    require(pair(pow(g, a), pow(h, b)).equals(pow(e, a.mul(b))),
            "bilinearity failed");
    require(pow(g, scalar(ctx, 0)).equals(G1(ctx)), "G1 identity exponent");
    require(g.mul(g).equals(pow(g, scalar(ctx, 2))), "G1 multiplication failed");
    require(h.mul(h).equals(pow(h, scalar(ctx, 2))), "G2 multiplication failed");
    require(e.mul(e).equals(pow(e, scalar(ctx, 2))), "GT multiplication failed");
    require(g.equals(g_before) && h.equals(h_before), "read-only operands changed");

    // Equal parameter text/labels do not make independently owned contexts compatible.
    auto other = context(params);
    auto other_scalar = scalar(other, 5);
    auto original = scalar(ctx, 13);
    rejects<std::invalid_argument>([&] { original = other_scalar; });
    require(original.equals(scalar(ctx, 13)), "failed copy assignment changed target");
    rejects<std::invalid_argument>([&] { original = std::move(other_scalar); });
    require(other_scalar.has_value(), "failed move assignment consumed source");
    require(original.equals(scalar(ctx, 13)), "failed move assignment changed target");
    rejects<std::invalid_argument>([&] { (void)original.mul(other_scalar); });
    rejects<std::invalid_argument>([&] { (void)original.equals(other_scalar); });
    rejects<std::invalid_argument>([&] { (void)pair(g, G2(other)); });
    rejects<std::invalid_argument>([&] { (void)pow(g, other_scalar); });
    rejects<std::invalid_argument>([&] { (void)pow(h, other_scalar); });
    rejects<std::invalid_argument>([&] { (void)pow(e, other_scalar); });

    auto moved = std::move(original);
    rejects<std::logic_error>([&] { (void)inverse(original); });
    rejects<std::logic_error>([&] { (void)pow(g, original); });
    original = scalar(ctx, 17);
    require(original.equals(scalar(ctx, 17)), "moved-from assignment failed");
    auto* self = &moved;
    moved = *self;
    moved = std::move(*self);
    require(moved.equals(scalar(ctx, 13)), "self assignment corrupted value");
    auto moved_context = std::move(alias);
    rejects<std::logic_error>([&] { (void)Scalar(alias); });
    rejects<std::logic_error>([&] { (void)alias.parameter_id(); });
    require(scalar(moved_context, 3).equals(a), "moved context lost ownership");

    // No user-visible context remains, but the elements must keep the pairing alive.
    auto escaped = [&] {
        auto ephemeral = context(params);
        return std::make_pair(nonidentity<G1>(ephemeral), nonidentity<G2>(ephemeral));
    }();
    const auto escaped_pairing = pair(escaped.first, escaped.second);
    require(escaped_pairing.equals(pair(escaped.first, escaped.second)),
            "element did not retain context lifetime");

    rejects<std::invalid_argument>([] {
        (void)PairingContext::from_trusted_parameters("", "type a");
    });
    rejects<std::invalid_argument>([] {
        (void)PairingContext::from_trusted_parameters("id", "");
    });
    rejects<std::invalid_argument>([] {
        const std::string embedded("type a\0suffix", 13);
        (void)PairingContext::from_trusted_parameters("id", embedded);
    });
    std::cout << "PASS: ownership, moves, lifetime, group types, algebra, context rejection\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        const bool reject_composite = argc == 3 && std::string(argv[1]) == "--reject-composite";
        if (argc != 2 && !reject_composite) {
            throw std::invalid_argument("expected trusted fixture path");
        }
        std::ifstream input(argv[reject_composite ? 2 : 1]);
        if (!input) throw std::runtime_error("could not read parameter fixture");
        const std::string params{std::istreambuf_iterator<char>(input), {}};
        if (reject_composite) {
            // Official PBC Type A1 fixture: init succeeds, then the adapter's
            // prime-order check rejects. Exercise destruction after successful
            // PBC initialization, rather than feeding its parser broken input.
            for (int i = 0; i < 3; ++i) {
                try {
                    (void)context(params);
                } catch (const std::invalid_argument& e) {
                    require(std::string(e.what()) == "PBC adapter requires a prime scalar order",
                            "fixture rejected before scalar-order check");
                    continue;
                }
                throw std::runtime_error("composite scalar order accepted");
            }
            return 0;
        }
        run(params);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
