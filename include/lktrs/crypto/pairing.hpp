#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lktrs::crypto {
namespace detail {
struct PairingState;
struct ElementStorage;
struct Access;
}

enum class Domain { scalar, g1, g2, gt };
template<Domain D> class Element;
class PairingContext;

// Single-threaded research adapter. Inputs must be trusted parameter fixtures.
// Not an adversarial parameter parser, security validator, or final protocol setup.
class PairingContext final {
public:
    static PairingContext from_trusted_parameters(
        std::string parameter_id, std::string_view contents);
    const std::string& parameter_id() const;
    std::size_t scalar_order_bits() const;

private:
    explicit PairingContext(std::shared_ptr<detail::PairingState>);
    std::shared_ptr<detail::PairingState> state_;
    template<Domain D> friend class Element;
    friend struct detail::Access;
};

template<Domain D>
class Element final {
    static_assert(D == Domain::scalar || D == Domain::g1 ||
                  D == Domain::g2 || D == Domain::gt);
public:
    // Scalar starts at zero; groups start at the identity.
    explicit Element(const PairingContext&);
    Element(const Element&);
    Element(Element&&) noexcept;
    Element& operator=(const Element&);
    Element& operator=(Element&&);
    ~Element();

    bool has_value() const noexcept;
    bool equals(const Element&) const;
    bool is_zero() const;      // scalar only: rejects group instantiations
    bool is_identity() const;  // group only: rejects the scalar instantiation
    Element mul(const Element&) const;
    Element inverse() const;   // group only: rejects the scalar instantiation
    Element negate() const;    // scalar only: rejects group instantiations

    // Canonical fixed-length encoding: exactly byte_length() bytes, big-endian,
    // left-zero-padded. Independent of the value (unlike raw element_to_bytes,
    // which drops leading zeros). This is a research encoding, not a finalized
    // wire format and not a validity check.
    std::size_t byte_length() const;
    std::vector<std::uint8_t> to_bytes() const;

    // Uses PBC's configured RNG. Testing only; final entropy policy is not selected.
    // The result may be zero/the identity.
    static Element sample_for_testing(const PairingContext&);
    // Decodes byte_length() bytes. Rejects a wrong length, a non-canonical
    // (value >= scalar order) scalar encoding, and out-of-domain group bytes.
    static Element from_bytes(const PairingContext&, const std::vector<std::uint8_t>&);
    // Domain-separated SHA-256 derivation, reduced modulo the scalar order and
    // retried on a zero result so the output is always a nonzero residue usable
    // as an exponent or an invertible Fiat-Shamir challenge.
    static Element hash_to_scalar(const PairingContext&, std::string_view domain,
                                  const std::vector<std::uint8_t>& message);

private:
    explicit Element(std::shared_ptr<detail::PairingState>);
    std::unique_ptr<detail::ElementStorage> storage_;
    friend struct detail::Access;
};

using Scalar = Element<Domain::scalar>;
using G1 = Element<Domain::g1>;
using G2 = Element<Domain::g2>;
using GT = Element<Domain::gt>;

// Integer conversion is modulo the scalar order, not a range/encoding check.
Scalar scalar(const PairingContext&, long value);
Scalar inverse(const Scalar&); // Rejects zero.
Scalar add(const Scalar&, const Scalar&);
Scalar sub(const Scalar&, const Scalar&);
Scalar mul(const Scalar&, const Scalar&);
// Non-zero scalar decoded from a canonical fixed-length big-endian encoding.
// This is what the scheme's counter-bound exponents (s+cnt+1, R/(R2-R1)) need.
Scalar non_zero_scalar_from_bytes(const PairingContext&, const std::vector<std::uint8_t>&);
G1 pow(const G1&, const Scalar&);
G2 pow(const G2&, const Scalar&);
GT pow(const GT&, const Scalar&);
GT pair(const G1&, const G2&);

extern template class Element<Domain::scalar>;
extern template class Element<Domain::g1>;
extern template class Element<Domain::g2>;
extern template class Element<Domain::gt>;
} // namespace lktrs::crypto
