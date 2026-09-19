#include "lktrs/crypto/ddh.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace lktrs::crypto {
namespace detail {

constexpr std::size_t kBytes = 32;
constexpr std::size_t kHashBytes = 64;

struct DdhState {
    explicit DdhState(std::string id) : parameter_id(std::move(id)) {}
    std::string parameter_id;
};

struct DdhScalarStorage {
    explicit DdhScalarStorage(std::shared_ptr<DdhState> owner)
        : state(std::move(owner)) {
        raw.fill(0);
    }
    ~DdhScalarStorage() { sodium_memzero(raw.data(), raw.size()); }
    DdhScalarStorage(const DdhScalarStorage&) = delete;
    DdhScalarStorage& operator=(const DdhScalarStorage&) = delete;

    std::shared_ptr<DdhState> state;
    std::array<unsigned char, kBytes> raw{};
};

struct DdhElementStorage {
    explicit DdhElementStorage(std::shared_ptr<DdhState> owner)
        : state(std::move(owner)) {
        raw.fill(0); // Ristretto's canonical identity encoding.
    }
    ~DdhElementStorage() { sodium_memzero(raw.data(), raw.size()); }
    DdhElementStorage(const DdhElementStorage&) = delete;
    DdhElementStorage& operator=(const DdhElementStorage&) = delete;

    std::shared_ptr<DdhState> state;
    std::array<unsigned char, kBytes> raw{};
};

struct DdhAccess {
    static const DdhScalarStorage& get(const DdhScalar& value) {
        if (!value.storage_) throw std::logic_error("operation on moved-from G_p scalar");
        return *value.storage_;
    }
    static DdhScalarStorage& get(DdhScalar& value) {
        if (!value.storage_) throw std::logic_error("operation on moved-from G_p scalar");
        return *value.storage_;
    }
    static const DdhElementStorage& get(const DdhElement& value) {
        if (!value.storage_) throw std::logic_error("operation on moved-from G_p element");
        return *value.storage_;
    }
    static DdhElementStorage& get(DdhElement& value) {
        if (!value.storage_) throw std::logic_error("operation on moved-from G_p element");
        return *value.storage_;
    }
    static DdhScalar make_scalar(const std::shared_ptr<DdhState>& state) {
        return DdhScalar(state);
    }
    static DdhElement make_element(const std::shared_ptr<DdhState>& state) {
        return DdhElement(state);
    }
    static std::shared_ptr<DdhState> context_state(const DdhContext& context) {
        if (!context.state_) throw std::logic_error("operation on moved-from G_p context");
        return context.state_;
    }
};

void require_same(const DdhScalarStorage& left, const DdhScalarStorage& right) {
    if (left.state != right.state) throw std::invalid_argument("different G_p contexts");
}
void require_same(const DdhElementStorage& left, const DdhElementStorage& right) {
    if (left.state != right.state) throw std::invalid_argument("different G_p contexts");
}

// The Ristretto255 scalar order L in little-endian form.  libsodium does not
// expose a scalar_is_canonical helper, so decoding performs this comparison
// before accepting bytes as a scalar.
constexpr std::array<unsigned char, kBytes> kScalarOrder = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

bool scalar_is_canonical(const std::array<unsigned char, kBytes>& value) {
    for (std::size_t index = kBytes; index-- > 0;) {
        if (value[index] != kScalarOrder[index]) return value[index] < kScalarOrder[index];
    }
    return false; // exactly L is not a residue in [0, L).
}

bool all_zero(const std::array<unsigned char, kBytes>& value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) { return byte == 0; });
}

void append_u64(std::vector<unsigned char>& out, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::length_error("hash input is too large");
    }
    const auto number = static_cast<std::uint64_t>(value);
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>(number >> shift));
    }
}

std::vector<unsigned char> hash_input(std::string_view domain,
                                      const std::vector<std::uint8_t>& message) {
    std::vector<unsigned char> input;
    input.reserve(16 + domain.size() + message.size());
    append_u64(input, domain.size());
    input.insert(input.end(), domain.begin(), domain.end());
    append_u64(input, message.size());
    input.insert(input.end(), message.begin(), message.end());
    return input;
}

std::array<unsigned char, kHashBytes> hash64(std::string_view domain,
                                             const std::vector<std::uint8_t>& message,
                                             std::uint64_t counter = 0) {
    auto input = hash_input(domain, message);
    if (counter != 0) {
        append_u64(input, sizeof(counter));
        for (int shift = 56; shift >= 0; shift -= 8) {
            input.push_back(static_cast<unsigned char>(counter >> shift));
        }
    }
    std::array<unsigned char, kHashBytes> digest{};
    if (crypto_generichash(digest.data(), digest.size(), input.data(), input.size(), nullptr, 0) != 0) {
        throw std::runtime_error("libsodium BLAKE2b hashing failed");
    }
    return digest;
}

} // namespace detail

DdhContext::DdhContext(std::shared_ptr<detail::DdhState> state)
    : state_(std::move(state)) {}

DdhContext DdhContext::ristretto255(std::string parameter_id) {
    if (parameter_id.empty()) throw std::invalid_argument("missing G_p parameter id");
    if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed");
    return DdhContext(std::make_shared<detail::DdhState>(std::move(parameter_id)));
}

const std::string& DdhContext::parameter_id() const {
    if (!state_) throw std::logic_error("operation on moved-from G_p context");
    return state_->parameter_id;
}

std::size_t DdhContext::scalar_order_bits() const {
    if (!state_) throw std::logic_error("operation on moved-from G_p context");
    return 253; // bit length of L = 2^252 + 27742317777372353535851937790883648493.
}

DdhScalar::DdhScalar(std::shared_ptr<detail::DdhState> context)
    : storage_(std::make_unique<detail::DdhScalarStorage>(std::move(context))) {
    if (!storage_->state) throw std::logic_error("operation on moved-from G_p context");
}
DdhScalar::DdhScalar(const DdhContext& context)
    : DdhScalar(detail::DdhAccess::context_state(context)) {}
DdhScalar::DdhScalar(const DdhScalar& other)
    : DdhScalar(detail::DdhAccess::get(other).state) {
    storage_->raw = detail::DdhAccess::get(other).raw;
}
DdhScalar::DdhScalar(DdhScalar&&) noexcept = default;
DdhScalar::~DdhScalar() = default;
DdhScalar& DdhScalar::operator=(const DdhScalar& other) {
    if (this == &other) return *this;
    const auto& source = detail::DdhAccess::get(other);
    if (storage_) detail::require_same(*storage_, source);
    DdhScalar replacement(other);
    storage_.swap(replacement.storage_);
    return *this;
}
DdhScalar& DdhScalar::operator=(DdhScalar&& other) {
    if (this == &other) return *this;
    const auto& source = detail::DdhAccess::get(other);
    if (storage_) detail::require_same(*storage_, source);
    storage_ = std::move(other.storage_);
    return *this;
}
bool DdhScalar::has_value() const noexcept { return static_cast<bool>(storage_); }
bool DdhScalar::equals(const DdhScalar& other) const {
    const auto& left = detail::DdhAccess::get(*this);
    const auto& right = detail::DdhAccess::get(other);
    detail::require_same(left, right);
    return sodium_memcmp(left.raw.data(), right.raw.data(), left.raw.size()) == 0;
}
bool DdhScalar::is_zero() const { return detail::all_zero(detail::DdhAccess::get(*this).raw); }
DdhScalar DdhScalar::negate() const {
    const auto& source = detail::DdhAccess::get(*this);
    auto result = detail::DdhAccess::make_scalar(source.state);
    crypto_core_ristretto255_scalar_negate(detail::DdhAccess::get(result).raw.data(),
                                           source.raw.data());
    return result;
}
DdhScalar DdhScalar::inverse() const {
    const auto& source = detail::DdhAccess::get(*this);
    if (detail::all_zero(source.raw)) throw std::domain_error("cannot invert zero G_p scalar");
    auto result = detail::DdhAccess::make_scalar(source.state);
    if (crypto_core_ristretto255_scalar_invert(detail::DdhAccess::get(result).raw.data(),
                                               source.raw.data()) != 0) {
        throw std::domain_error("cannot invert zero G_p scalar");
    }
    return result;
}
DdhScalar DdhScalar::mul(const DdhScalar& other) const {
    const auto& left = detail::DdhAccess::get(*this);
    const auto& right = detail::DdhAccess::get(other);
    detail::require_same(left, right);
    auto result = detail::DdhAccess::make_scalar(left.state);
    crypto_core_ristretto255_scalar_mul(detail::DdhAccess::get(result).raw.data(),
                                        left.raw.data(), right.raw.data());
    return result;
}
std::vector<std::uint8_t> DdhScalar::to_bytes() const {
    const auto& source = detail::DdhAccess::get(*this);
    return std::vector<std::uint8_t>(source.raw.begin(), source.raw.end());
}
std::size_t DdhScalar::byte_length() const {
    (void)detail::DdhAccess::get(*this);
    return detail::kBytes;
}
DdhScalar DdhScalar::from_bytes(const DdhContext& context,
                                const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != detail::kBytes) {
        throw std::invalid_argument("G_p scalar encoding has the wrong length");
    }
    DdhScalar result(context);
    auto& storage = detail::DdhAccess::get(result);
    std::copy(bytes.begin(), bytes.end(), storage.raw.begin());
    if (!detail::scalar_is_canonical(storage.raw)) {
        throw std::invalid_argument("G_p scalar encoding is not reduced modulo the order");
    }
    return result;
}
DdhScalar DdhScalar::sample_for_testing(const DdhContext& context) {
    DdhScalar result(context);
    crypto_core_ristretto255_scalar_random(detail::DdhAccess::get(result).raw.data());
    return result;
}
DdhScalar DdhScalar::sample_nonzero(const DdhContext& context) {
    DdhScalar result(context);
    do {
        crypto_core_ristretto255_scalar_random(detail::DdhAccess::get(result).raw.data());
    } while (result.is_zero());
    return result;
}
DdhScalar DdhScalar::hash_to_scalar(const DdhContext& context, std::string_view domain,
                                    const std::vector<std::uint8_t>& message) {
    DdhScalar result(context);
    for (std::uint64_t counter = 0;; ++counter) {
        const auto digest = detail::hash64(domain, message, counter);
        crypto_core_ristretto255_scalar_reduce(detail::DdhAccess::get(result).raw.data(),
                                               digest.data());
        if (!result.is_zero()) return result;
    }
}

DdhElement::DdhElement(std::shared_ptr<detail::DdhState> context)
    : storage_(std::make_unique<detail::DdhElementStorage>(std::move(context))) {
    if (!storage_->state) throw std::logic_error("operation on moved-from G_p context");
}
DdhElement::DdhElement(const DdhContext& context)
    : DdhElement(detail::DdhAccess::context_state(context)) {}
DdhElement::DdhElement(const DdhElement& other)
    : DdhElement(detail::DdhAccess::get(other).state) {
    storage_->raw = detail::DdhAccess::get(other).raw;
}
DdhElement::DdhElement(DdhElement&&) noexcept = default;
DdhElement::~DdhElement() = default;
DdhElement& DdhElement::operator=(const DdhElement& other) {
    if (this == &other) return *this;
    const auto& source = detail::DdhAccess::get(other);
    if (storage_) detail::require_same(*storage_, source);
    DdhElement replacement(other);
    storage_.swap(replacement.storage_);
    return *this;
}
DdhElement& DdhElement::operator=(DdhElement&& other) {
    if (this == &other) return *this;
    const auto& source = detail::DdhAccess::get(other);
    if (storage_) detail::require_same(*storage_, source);
    storage_ = std::move(other.storage_);
    return *this;
}
bool DdhElement::has_value() const noexcept { return static_cast<bool>(storage_); }
bool DdhElement::equals(const DdhElement& other) const {
    const auto& left = detail::DdhAccess::get(*this);
    const auto& right = detail::DdhAccess::get(other);
    detail::require_same(left, right);
    return sodium_memcmp(left.raw.data(), right.raw.data(), left.raw.size()) == 0;
}
bool DdhElement::is_identity() const { return detail::all_zero(detail::DdhAccess::get(*this).raw); }
DdhElement DdhElement::mul(const DdhElement& other) const {
    const auto& left = detail::DdhAccess::get(*this);
    const auto& right = detail::DdhAccess::get(other);
    detail::require_same(left, right);
    auto result = detail::DdhAccess::make_element(left.state);
    if (crypto_core_ristretto255_add(detail::DdhAccess::get(result).raw.data(),
                                     left.raw.data(), right.raw.data()) != 0) {
        throw std::runtime_error("libsodium Ristretto addition failed");
    }
    return result;
}
DdhElement DdhElement::inverse() const {
    const auto& source = detail::DdhAccess::get(*this);
    auto result = detail::DdhAccess::make_element(source.state);
    const std::array<unsigned char, detail::kBytes> identity{};
    if (crypto_core_ristretto255_sub(detail::DdhAccess::get(result).raw.data(), identity.data(),
                                     source.raw.data()) != 0) {
        throw std::runtime_error("libsodium Ristretto inversion failed");
    }
    return result;
}
std::vector<std::uint8_t> DdhElement::to_bytes() const {
    const auto& source = detail::DdhAccess::get(*this);
    return std::vector<std::uint8_t>(source.raw.begin(), source.raw.end());
}
std::size_t DdhElement::byte_length() const {
    (void)detail::DdhAccess::get(*this);
    return detail::kBytes;
}
DdhElement DdhElement::from_bytes(const DdhContext& context,
                                  const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != detail::kBytes) {
        throw std::invalid_argument("G_p element encoding has the wrong length");
    }
    DdhElement result(context);
    auto& storage = detail::DdhAccess::get(result);
    std::copy(bytes.begin(), bytes.end(), storage.raw.begin());
    if (crypto_core_ristretto255_is_valid_point(storage.raw.data()) != 1) {
        throw std::invalid_argument("invalid Ristretto255 point encoding");
    }
    return result;
}
DdhElement DdhElement::sample_for_testing(const DdhContext& context) {
    DdhElement result(context);
    crypto_core_ristretto255_random(detail::DdhAccess::get(result).raw.data());
    return result;
}
DdhElement DdhElement::generator(const DdhContext& context) {
    DdhElement result(context);
    std::array<unsigned char, detail::kBytes> one{};
    one[0] = 1;
    if (crypto_scalarmult_ristretto255_base(detail::DdhAccess::get(result).raw.data(), one.data()) != 0) {
        throw std::runtime_error("libsodium Ristretto base multiplication failed");
    }
    return result;
}
DdhElement DdhElement::hash_to_group(const DdhContext& context, std::string_view domain,
                                     const std::vector<std::uint8_t>& message) {
    DdhElement result(context);
    const auto digest = detail::hash64(domain, message);
    if (crypto_core_ristretto255_from_hash(detail::DdhAccess::get(result).raw.data(), digest.data()) != 0) {
        throw std::runtime_error("libsodium Ristretto hash-to-group failed");
    }
    return result;
}

GpScalar scalar(const DdhContext& context, long value) {
    GpScalar result(context);
    std::array<unsigned char, 64> wide{};
    const bool negative = value < 0;
    unsigned long magnitude = 0;
    if (negative) {
        // Avoid signed overflow for LONG_MIN.
        magnitude = static_cast<unsigned long>(-(value + 1));
        ++magnitude;
    } else {
        magnitude = static_cast<unsigned long>(value);
    }
    for (std::size_t i = 0; magnitude != 0 && i < wide.size(); ++i) {
        wide[i] = static_cast<unsigned char>(magnitude & 0xffU);
        magnitude >>= 8;
    }
    crypto_core_ristretto255_scalar_reduce(detail::DdhAccess::get(result).raw.data(), wide.data());
    if (negative) result = result.negate();
    return result;
}
GpScalar add(const GpScalar& left, const GpScalar& right) {
    const auto& a = detail::DdhAccess::get(left);
    const auto& b = detail::DdhAccess::get(right);
    detail::require_same(a, b);
    auto result = detail::DdhAccess::make_scalar(a.state);
    crypto_core_ristretto255_scalar_add(detail::DdhAccess::get(result).raw.data(), a.raw.data(), b.raw.data());
    return result;
}
GpScalar sub(const GpScalar& left, const GpScalar& right) {
    const auto& a = detail::DdhAccess::get(left);
    const auto& b = detail::DdhAccess::get(right);
    detail::require_same(a, b);
    auto result = detail::DdhAccess::make_scalar(a.state);
    crypto_core_ristretto255_scalar_sub(detail::DdhAccess::get(result).raw.data(), a.raw.data(), b.raw.data());
    return result;
}
GpScalar mul(const GpScalar& left, const GpScalar& right) { return left.mul(right); }
GpScalar inverse(const GpScalar& value) { return value.inverse(); }
Gp pow(const Gp& base, const GpScalar& exponent) {
    const auto& point = detail::DdhAccess::get(base);
    const auto& scalar_value = detail::DdhAccess::get(exponent);
    if (point.state != scalar_value.state) throw std::invalid_argument("different G_p contexts");
    auto result = detail::DdhAccess::make_element(point.state);
    if (detail::all_zero(point.raw) || detail::all_zero(scalar_value.raw)) return result;
    if (crypto_scalarmult_ristretto255(detail::DdhAccess::get(result).raw.data(), scalar_value.raw.data(),
                                       point.raw.data()) != 0) {
        throw std::runtime_error("libsodium Ristretto scalar multiplication failed");
    }
    return result;
}
Gp gp_generator(const DdhContext& context) { return Gp::generator(context); }
Gp hash_to_group_Gp(const DdhContext& context, std::string_view domain,
                    const std::vector<std::uint8_t>& message) {
    return Gp::hash_to_group(context, domain, message);
}

} // namespace lktrs::crypto
