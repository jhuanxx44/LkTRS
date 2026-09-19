#ifndef LKTRS_CRYPTO_SHA256_HPP
#define LKTRS_CRYPTO_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace lktrs::crypto {

// Self-contained SHA-256 (FIPS 180-4). This exists so the research harness has a
// cryptographic hash with no external dependency. It is not constant-time and
// has not been audited; do not use it for secrets in production.
std::array<std::uint8_t, 32> sha256(const std::uint8_t* data, std::size_t length);

inline std::array<std::uint8_t, 32> sha256(std::string_view text) {
    return sha256(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

inline std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    return sha256(data.data(), data.size());
}

} // namespace lktrs::crypto

#endif
