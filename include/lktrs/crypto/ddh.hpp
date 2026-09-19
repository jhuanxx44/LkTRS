#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lktrs::crypto {
namespace detail {
struct DdhState;
struct DdhElementStorage;
struct DdhScalarStorage;
struct DdhAccess;
} // namespace detail

// Standalone prime-order group used for the paper's G_p values.  The current
// backend is Ristretto255 from libsodium.  Ristretto's additive API is exposed
// with the multiplicative names used by the Lk-TRS equations: mul() is group
// multiplication, inverse() is the group inverse, and pow() is scalar
// exponentiation.
class DdhContext final {
public:
    static DdhContext ristretto255(std::string parameter_id = "ristretto255");

    const std::string& parameter_id() const;
    std::size_t scalar_order_bits() const;
    std::size_t scalar_order_bytes() const noexcept { return 32; }
    static constexpr std::size_t element_bytes() noexcept { return 32; }

private:
    explicit DdhContext(std::shared_ptr<detail::DdhState>);
    std::shared_ptr<detail::DdhState> state_;
    friend class DdhElement;
    friend class DdhScalar;
    friend struct detail::DdhAccess;
};

class DdhScalar final {
public:
    // Scalar starts at zero.  The constructor is intentionally explicit so a
    // pairing Scalar cannot be mixed with a G_p scalar by accident.
    explicit DdhScalar(const DdhContext&);
    DdhScalar(const DdhScalar&);
    DdhScalar(DdhScalar&&) noexcept;
    DdhScalar& operator=(const DdhScalar&);
    DdhScalar& operator=(DdhScalar&&);
    ~DdhScalar();

    bool has_value() const noexcept;
    bool equals(const DdhScalar&) const;
    bool is_zero() const;
    DdhScalar negate() const;
    DdhScalar inverse() const; // rejects zero

    std::size_t byte_length() const;
    std::vector<std::uint8_t> to_bytes() const;
    static DdhScalar from_bytes(const DdhContext&, const std::vector<std::uint8_t>&);
    static DdhScalar sample_for_testing(const DdhContext&);
    static DdhScalar sample_nonzero(const DdhContext&);
    static DdhScalar hash_to_scalar(const DdhContext&, std::string_view domain,
                                    const std::vector<std::uint8_t>& message);

    DdhScalar mul(const DdhScalar&) const;

private:
    explicit DdhScalar(std::shared_ptr<detail::DdhState>);
    std::unique_ptr<detail::DdhScalarStorage> storage_;
    friend struct detail::DdhAccess;
};

class DdhElement final {
public:
    // Group starts at the identity.
    explicit DdhElement(const DdhContext&);
    DdhElement(const DdhElement&);
    DdhElement(DdhElement&&) noexcept;
    DdhElement& operator=(const DdhElement&);
    DdhElement& operator=(DdhElement&&);
    ~DdhElement();

    bool has_value() const noexcept;
    bool equals(const DdhElement&) const;
    bool is_identity() const;
    DdhElement mul(const DdhElement&) const;
    DdhElement inverse() const;

    std::size_t byte_length() const;
    std::vector<std::uint8_t> to_bytes() const;
    static DdhElement from_bytes(const DdhContext&, const std::vector<std::uint8_t>&);
    static DdhElement sample_for_testing(const DdhContext&);
    static DdhElement generator(const DdhContext&);
    static DdhElement hash_to_group(const DdhContext&, std::string_view domain,
                                    const std::vector<std::uint8_t>& message);

private:
    explicit DdhElement(std::shared_ptr<detail::DdhState>);
    std::unique_ptr<detail::DdhElementStorage> storage_;
    friend struct detail::DdhAccess;
};

using Gp = DdhElement;
using GpScalar = DdhScalar;
using GpElement = DdhElement;
using DdhGroup = DdhElement;

GpScalar scalar(const DdhContext&, long value);
GpScalar add(const GpScalar&, const GpScalar&);
GpScalar sub(const GpScalar&, const GpScalar&);
GpScalar mul(const GpScalar&, const GpScalar&);
GpScalar inverse(const GpScalar&);
Gp pow(const Gp&, const GpScalar&);

// Named aliases make the setup code read like the paper: u is the fixed
// generator and u_t is hash_to_group(issue).  Both return the same typed G_p.
Gp gp_generator(const DdhContext&);
Gp hash_to_group_Gp(const DdhContext&, std::string_view domain,
                    const std::vector<std::uint8_t>& message);

} // namespace lktrs::crypto
