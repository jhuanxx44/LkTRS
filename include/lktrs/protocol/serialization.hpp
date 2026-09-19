#pragma once

#include "lktrs/protocol/clear.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace lktrs::protocol {

// Versioned, length-prefixed encodings used by the clear reference and the
// future native proof statement. These bytes are a transcript format, not a
// wire format for production keys until the native profile is frozen.
std::vector<std::uint8_t> encode_ring_label(const RingLabel& label);
RingLabel decode_ring_label(const crypto::PairingContext& pairing,
                            const crypto::DdhContext& ddh,
                            const std::vector<std::uint8_t>& bytes);
std::vector<std::uint8_t> encode_challenge_transcript(const RingLabel& label,
                                                       std::string_view message,
                                                       const crypto::G1& nym,
                                                       std::uint64_t timestamp);
std::vector<std::uint8_t> encode_public_signature(const ClearSignature& signature);

struct PublicSignature final {
    crypto::G1 nym;
    crypto::G1 accumulator_value;
    crypto::Gp one_time_pass;
    crypto::Gp trace_tag;
    crypto::Scalar challenge;
    std::uint64_t timestamp = 0;
};

PublicSignature decode_public_signature(const crypto::PairingContext& pairing,
                                        const crypto::DdhContext& ddh,
                                        const std::vector<std::uint8_t>& bytes);

} // namespace lktrs::protocol
