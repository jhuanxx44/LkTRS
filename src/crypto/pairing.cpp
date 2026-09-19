#include "lktrs/crypto/pairing.hpp"

#include "lktrs/crypto/sha256.hpp"

#include <gmp.h>
#include <pbc/pbc.h>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace lktrs::crypto {
namespace detail {

constexpr bool is_scalar(Domain domain) { return domain == Domain::scalar; }

template<Domain D>
void require_scalar_domain(const char* operation) {
    if constexpr (!is_scalar(D)) {
        (void)operation;
        throw std::logic_error(std::string(operation) + " is scalar-domain only");
    }
}

template<Domain D>
void require_group_domain(const char* operation) {
    if constexpr (is_scalar(D)) {
        (void)operation;
        throw std::logic_error(std::string(operation) + " is group-domain only");
    }
}

// Fixed-length big-endian conversion. mpz_export drops leading zero bytes and
// writes nothing at all for zero, so the caller supplies the target width.
std::vector<std::uint8_t> mpz_to_fixed_bytes(const mpz_t value, std::size_t width) {
    std::vector<std::uint8_t> out(width, 0);
    if (width == 0) return out;
    std::size_t written = 0;
    mpz_export(out.data(), &written, /*order=*/1, /*size=*/1, /*endian=*/0,
               /*nails=*/0, value);
    if (written > width) throw std::logic_error("value does not fit encoding width");
    if (written != 0 && written < width) {
        std::move_backward(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(written),
                           out.end());
        std::fill(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(width - written), 0);
    }
    return out;
}

void mpz_from_fixed_bytes(mpz_t out, const std::uint8_t* data, std::size_t length) {
    mpz_import(out, length, /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, data);
}

struct PairingState {
    explicit PairingState(std::string id) : parameter_id(std::move(id)) {}
    ~PairingState() {
        if (initialized) pairing_clear(raw);
    }
    PairingState(const PairingState&) = delete;
    PairingState& operator=(const PairingState&) = delete;

    std::string parameter_id;
    pairing_t raw{};
    bool initialized = false;
};

struct ElementStorage {
    ElementStorage(std::shared_ptr<PairingState> context, Domain domain)
        : state(std::move(context)) {
        switch (domain) {
        case Domain::scalar: element_init_Zr(raw, state->raw); break;
        case Domain::g1: element_init_G1(raw, state->raw); break;
        case Domain::g2: element_init_G2(raw, state->raw); break;
        case Domain::gt: element_init_GT(raw, state->raw); break;
        }
        if (domain == Domain::scalar) element_set0(raw);
        else element_set1(raw);
    }
    ~ElementStorage() { element_clear(raw); }
    ElementStorage(const ElementStorage&) = delete;
    ElementStorage& operator=(const ElementStorage&) = delete;

    // This owner remains alive throughout element_clear.
    std::shared_ptr<PairingState> state;
    // PBC source operands lack const; only logically read-only input operations
    // use this bridge. No raw writable handle is exposed to callers.
    mutable element_t raw{};
};

struct Access {
    template<Domain D>
    static const ElementStorage& get(const Element<D>& value) {
        if (!value.storage_) {
            throw std::logic_error("operation on moved-from PBC element");
        }
        return *value.storage_;
    }
    template<Domain D>
    static Element<D> make(std::shared_ptr<PairingState> context) {
        return Element<D>(std::move(context));
    }
    // Bridge for free functions that must evaluate a new element against the
    // context's group order without taking a public dependency on PairingState.
    static std::shared_ptr<PairingState> context_state(const PairingContext& context) {
        if (!context.state_) {
            throw std::logic_error("operation on moved-from pairing context");
        }
        return context.state_;
    }
};

static void require_same(const ElementStorage& a, const ElementStorage& b) {
    if (a.state != b.state) {
        throw std::invalid_argument("different PBC pairing contexts");
    }
}

template<Domain D>
Element<D> group_pow(const Element<D>& base, const Scalar& exponent) {
    const auto& a = Access::get(base);
    const auto& b = Access::get(exponent);
    require_same(a, b);
    auto result = Access::make<D>(a.state);
    element_pow_zn(Access::get(result).raw, a.raw, b.raw);
    return result;
}
} // namespace detail

PairingContext::PairingContext(std::shared_ptr<detail::PairingState> state)
    : state_(std::move(state)) {}

PairingContext PairingContext::from_trusted_parameters(
    std::string id, std::string_view text) {
    if (id.empty() || text.empty() || text.size() > 1024 * 1024 ||
        text.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("missing or invalid trusted parameter text/id");
    }
    auto owner = std::make_shared<detail::PairingState>(std::move(id));
    if (pairing_init_set_buf(owner->raw, text.data(), text.size()) != 0) {
        // PBC reports no initialized pairing on failure. Do not pairing_clear it.
        // This does not make the underlying parser safe for untrusted inputs.
        throw std::runtime_error("PBC parameter initialization failed");
    }
    owner->initialized = true;
    // Scalar inversion needs a field. This is only an order sanity check,
    // not validation of a curve, subgroup encoding, or claimed security level.
    if (mpz_cmp_ui(owner->raw->r, 2) <= 0 ||
        mpz_probab_prime_p(owner->raw->r, 32) == 0) {
        throw std::invalid_argument("PBC adapter requires a prime scalar order");
    }
    return PairingContext(std::move(owner));
}

const std::string& PairingContext::parameter_id() const {
    if (!state_) throw std::logic_error("operation on moved-from pairing context");
    return state_->parameter_id;
}

std::size_t PairingContext::scalar_order_bits() const {
    if (!state_) throw std::logic_error("operation on moved-from pairing context");
    return mpz_sizeinbase(state_->raw->r, 2);
}

template<Domain D>
Element<D>::Element(std::shared_ptr<detail::PairingState> context) {
    if (!context) throw std::logic_error("operation on moved-from pairing context");
    storage_ = std::make_unique<detail::ElementStorage>(std::move(context), D);
}
template<Domain D>
Element<D>::Element(const PairingContext& context) : Element(context.state_) {}
template<Domain D>
Element<D>::Element(const Element& other)
    : Element(detail::Access::get(other).state) {
    element_set(storage_->raw, detail::Access::get(other).raw);
}
template<Domain D>
Element<D>::Element(Element&&) noexcept = default;
template<Domain D>
Element<D>::~Element() = default;

template<Domain D>
Element<D>& Element<D>::operator=(const Element& other) {
    if (this == &other) return *this;
    const auto& source = detail::Access::get(other);
    if (storage_) detail::require_same(*storage_, source);
    Element replacement(other);
    storage_.swap(replacement.storage_);
    return *this;
}
template<Domain D>
Element<D>& Element<D>::operator=(Element&& other) {
    if (this == &other) return *this;
    const auto& source = detail::Access::get(other);
    if (storage_) detail::require_same(*storage_, source);
    storage_ = std::move(other.storage_);
    return *this;
}
template<Domain D>
bool Element<D>::has_value() const noexcept { return static_cast<bool>(storage_); }
template<Domain D>
bool Element<D>::equals(const Element& other) const {
    const auto& a = detail::Access::get(*this);
    const auto& b = detail::Access::get(other);
    detail::require_same(a, b);
    return element_cmp(a.raw, b.raw) == 0;
}
template<Domain D>
Element<D> Element<D>::mul(const Element& other) const {
    const auto& a = detail::Access::get(*this);
    const auto& b = detail::Access::get(other);
    detail::require_same(a, b);
    auto result = detail::Access::make<D>(a.state);
    element_mul(detail::Access::get(result).raw, a.raw, b.raw);
    return result;
}
template<Domain D>
bool Element<D>::is_zero() const {
    detail::require_scalar_domain<D>("is_zero");
    return element_is0(detail::Access::get(*this).raw) != 0;
}
template<Domain D>
bool Element<D>::is_identity() const {
    detail::require_group_domain<D>("is_identity");
    return element_is1(detail::Access::get(*this).raw) != 0;
}
template<Domain D>
Element<D> Element<D>::negate() const {
    detail::require_scalar_domain<D>("negate");
    const auto& a = detail::Access::get(*this);
    auto result = detail::Access::make<D>(a.state);
    element_neg(detail::Access::get(result).raw, a.raw);
    return result;
}
template<Domain D>
Element<D> Element<D>::inverse() const {
    detail::require_group_domain<D>("inverse");
    const auto& a = detail::Access::get(*this);
    // The identity is its own inverse, so a well-formed group inverse accepts it.
    // Rejecting it here conflated "the additive identity of the scalar field"
    // with "the identity element of a group", and would break generic group
    // division whenever a legal elimination produced the identity (e.g. after
    // pow(g, 0) or a cancellation). Degeneracy checks belong at the protocol
    // entries that actually require a non-identity element, not in the inverse.
    auto result = detail::Access::make<D>(a.state);
    element_invert(detail::Access::get(result).raw, a.raw);
    return result;
}
template<Domain D>
std::size_t Element<D>::byte_length() const {
    const auto length = element_length_in_bytes(detail::Access::get(*this).raw);
    if (length <= 0) throw std::runtime_error("PBC reported a non-positive element length");
    return static_cast<std::size_t>(length);
}
namespace detail {
// Type A has a lossy identity encoding that PBC does not report.
//
// `element_to_bytes` writes 128 zero bytes for the G1 and G2 identity, but
// `element_from_bytes` on those same bytes does NOT return the identity: it
// returns a different, specious raw state whose own re-encoding happens to be
// all zeros again. The bytes round-trip while the group element does not, so a
// byte-equality check cannot detect it (this is the M1 regression).
//
// We therefore treat the all-zero pattern as a reserved sentinel and map it back
// to the identity ourselves. The sentinel is unambiguous for G1/G2: it is the
// only pattern for which PBC's decoder fails to reproduce the encoded element,
// and it is what `element_to_bytes` already emits for the identity, so no
// non-identity element with a faithful encoding can collide with it.
bool all_zero(const std::vector<std::uint8_t>& bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}
} // namespace detail

template<Domain D>
std::vector<std::uint8_t> Element<D>::to_bytes() const {
    const auto& a = detail::Access::get(*this);
    const auto width = byte_length();
    std::vector<std::uint8_t> buffer(width);
    // Emit the identity sentinel directly. Note this is what PBC writes anyway
    // for G1/G2; doing it explicitly keeps the sentinel a deliberate part of our
    // format rather than an accident of the backend.
    if constexpr (!detail::is_scalar(D)) {
        if (element_is1(a.raw)) return buffer;
    }
    const auto written = static_cast<std::size_t>(element_to_bytes(buffer.data(), a.raw));
    // PBC drops leading zeros for some fields, so re-emit at a fixed width. The
    // underlying integer is big-endian in both paths.
    if (written > width) throw std::runtime_error("PBC wrote more bytes than it declared");
    if (written < width) {
        std::move_backward(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(written),
                           buffer.end());
        std::fill(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(width - written), 0);
    }
    return buffer;
}
// Research-level canonicality check for scalars. The decoded integer must be
// strictly less than the scalar order.
//
// This deliberately compares encoded bytes rather than integers. PBC's
// element_to_mpz applies a truncating 2^(k-1) reduction to a Zr element that is
// already out of range, so an integer read-back can silently mask exactly the
// malformed encodings this check exists to catch.
namespace detail {
std::vector<std::uint8_t> order_bytes(const ElementStorage& storage) {
    mpz_t order;
    mpz_init_set(order, storage.state->raw->r);
    const auto width = static_cast<std::size_t>(element_length_in_bytes(storage.raw));
    auto encoded = mpz_to_fixed_bytes(order, width);
    mpz_clear(order);
    if (encoded.size() != width) {
        throw std::logic_error("scalar order does not fit the declared element width");
    }
    return encoded;
}

void require_canonical_scalar(const ElementStorage& storage,
                              const std::vector<std::uint8_t>& encoded,
                              const char* label) {
    const auto bound = order_bytes(storage);
    if (encoded.size() != bound.size() || !std::lexicographical_compare(encoded.begin(), encoded.end(),
                                                                       bound.begin(), bound.end())) {
        throw std::invalid_argument(label);
    }
}
} // namespace detail

template<Domain D>
Element<D> Element<D>::from_bytes(const PairingContext& context,
                                  const std::vector<std::uint8_t>& bytes) {
    if (!context.state_) throw std::logic_error("operation on moved-from pairing context");
    Element result(context);
    const auto& storage = detail::Access::get(result);
    const auto width = static_cast<std::size_t>(
        element_length_in_bytes(storage.raw));
    if (bytes.size() != width) {
        throw std::invalid_argument("element encoding has the wrong length");
    }
    if constexpr (detail::is_scalar(D)) {
        const auto consumed = static_cast<std::size_t>(
            element_from_bytes(storage.raw, bytes.data()));
        if (consumed != bytes.size()) {
            throw std::invalid_argument("element encoding was not fully consumed");
        }
        detail::require_canonical_scalar(
            storage, bytes, "scalar encoding is not reduced modulo the order");
        return result;
    }
    // Reserved identity sentinel: decode it to the identity rather than handing
    // the bytes to PBC's lossy Type A parser (see detail::all_zero above).
    if (detail::all_zero(bytes)) {
        element_set1(storage.raw);
        return result;
    }
    const auto consumed = static_cast<std::size_t>(
        element_from_bytes(storage.raw, bytes.data()));
    if (consumed != bytes.size()) {
        throw std::invalid_argument("element encoding was not fully consumed");
    }
    // Research-level group canonicality check: a non-canonical encoding does not
    // survive a decode/encode round trip. This is not a curve-membership or
    // subgroup-membership proof, and the underlying PBC parser is not hardened.
    if (result.to_bytes() != bytes) {
        throw std::invalid_argument("element encoding is not canonical");
    }
    return result;
}
template<Domain D>
Element<D> Element<D>::sample_for_testing(const PairingContext& context) {
    Element result(context);
    element_random(result.storage_->raw);
    return result;
}

Scalar scalar(const PairingContext& context, long value) {
    Scalar result(context);
    element_set_si(detail::Access::get(result).raw, value);
    return result;
}
Scalar inverse(const Scalar& value) {
    const auto& input = detail::Access::get(value);
    if (element_is0(input.raw)) throw std::domain_error("inverse of zero scalar");
    auto result = detail::Access::make<Domain::scalar>(input.state);
    element_invert(detail::Access::get(result).raw, input.raw);
    return result;
}
static Scalar binary_scalar(const Scalar& first, const Scalar& second, char operation) {
    const auto& a = detail::Access::get(first);
    const auto& b = detail::Access::get(second);
    detail::require_same(a, b);
    auto result = detail::Access::make<Domain::scalar>(a.state);
    auto& raw = detail::Access::get(result).raw;
    switch (operation) {
    case '+': element_add(raw, a.raw, b.raw); break;
    case '-': element_sub(raw, a.raw, b.raw); break;
    case '*': element_mul(raw, a.raw, b.raw); break;
    default: throw std::logic_error("unsupported scalar operation");
    }
    return result;
}
Scalar add(const Scalar& first, const Scalar& second) {
    return binary_scalar(first, second, '+');
}
Scalar sub(const Scalar& first, const Scalar& second) {
    return binary_scalar(first, second, '-');
}
Scalar mul(const Scalar& first, const Scalar& second) {
    return binary_scalar(first, second, '*');
}
Scalar non_zero_scalar_from_bytes(const PairingContext& context,
                                  const std::vector<std::uint8_t>& bytes) {
    // from_bytes has already rejected a non-reduced (>= order) encoding.
    auto value = Scalar::from_bytes(context, bytes);
    if (value.is_zero()) throw std::domain_error("scalar encoding decoded to zero");
    return value;
}

// Scalar-only body. Kept out of the template so the non-scalar instantiations
// below are trivial to compile and cannot reach PBC scalar internals.
static Scalar derive_scalar(const PairingContext& context, std::string_view domain,
                            const std::vector<std::uint8_t>& message) {
    const auto state = detail::Access::context_state(context);
    // Domain-separated, length-prefixed digest so that (domain, message) pairs
    // cannot be re-parsed into a different pair.
    std::vector<std::uint8_t> input;
    input.reserve(domain.size() + message.size() + 16);
    const auto push_u64 = [&input](std::uint64_t value) {
        for (int i = 7; i >= 0; --i) {
            input.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
        }
    };
    push_u64(domain.size());
    input.insert(input.end(), domain.begin(), domain.end());
    push_u64(message.size());
    input.insert(input.end(), message.begin(), message.end());

    // A 256-bit digest is normally wider than the scalar order, so the digest is
    // reduced modulo the order here. Retrying on a zero residue keeps the result
    // invertible and makes the bias from reduction negligible.
    mpz_t digest_value;
    mpz_init(digest_value);
    auto result = detail::Access::make<Domain::scalar>(state);
    for (std::uint32_t attempt = 0; attempt < 64; ++attempt) {
        auto block = input;
        if (attempt != 0) {
            block.push_back(static_cast<std::uint8_t>(attempt >> 24));
            block.push_back(static_cast<std::uint8_t>(attempt >> 16));
            block.push_back(static_cast<std::uint8_t>(attempt >> 8));
            block.push_back(static_cast<std::uint8_t>(attempt));
        }
        const auto digest = sha256(block);
        mpz_import(digest_value, digest.size(), /*order=*/1, /*size=*/1,
                   /*endian=*/0, /*nails=*/0, digest.data());
        mpz_mod(digest_value, digest_value, state->raw->r);
        if (mpz_sgn(digest_value) != 0) {
            element_set_mpz(detail::Access::get(result).raw, digest_value);
            mpz_clear(digest_value);
            return result;
        }
    }
    mpz_clear(digest_value);
    throw std::runtime_error("hash_to_scalar failed to derive a nonzero residue");
}

template<Domain D>
Element<D> Element<D>::hash_to_scalar(const PairingContext& context, std::string_view domain,
                                     const std::vector<std::uint8_t>& message) {
    if constexpr (D != Domain::scalar) {
        (void)context;
        (void)domain;
        (void)message;
        throw std::logic_error("hash_to_scalar is only defined for scalars");
    } else {
        return derive_scalar(context, domain, message);
    }
}

G1 pow(const G1& base, const Scalar& exponent) {
    return detail::group_pow(base, exponent);
}
G2 pow(const G2& base, const Scalar& exponent) {
    return detail::group_pow(base, exponent);
}
GT pow(const GT& base, const Scalar& exponent) {
    return detail::group_pow(base, exponent);
}
GT pair(const G1& first, const G2& second) {
    const auto& a = detail::Access::get(first);
    const auto& b = detail::Access::get(second);
    detail::require_same(a, b);
    auto result = detail::Access::make<Domain::gt>(a.state);
    pairing_apply(detail::Access::get(result).raw, a.raw, b.raw, a.state->raw);
    return result;
}
template class Element<Domain::scalar>;
template class Element<Domain::g1>;
template class Element<Domain::g2>;
template class Element<Domain::gt>;
} // namespace lktrs::crypto
