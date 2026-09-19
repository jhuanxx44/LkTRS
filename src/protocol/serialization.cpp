#include "lktrs/protocol/serialization.hpp"

#include <limits>
#include <stdexcept>

namespace lktrs::protocol {
namespace {

constexpr std::size_t max_serialized_bytes = 16 * 1024 * 1024;
constexpr std::uint64_t max_field_bytes = 1 * 1024 * 1024;

class Reader final {
public:
    explicit Reader(const std::vector<std::uint8_t>& bytes) : bytes_(bytes) {
        if (bytes_.size() > max_serialized_bytes) throw std::length_error("serialization exceeds 16 MiB");
    }

    std::uint8_t byte(const char* label) {
        if (offset_ >= bytes_.size()) throw std::invalid_argument(label);
        return bytes_[offset_++];
    }
    std::uint64_t u64(const char* label) {
        if (bytes_.size() - offset_ < 8) throw std::invalid_argument(label);
        std::uint64_t value = 0;
        for (int shift = 56; shift >= 0; shift -= 8) value |= static_cast<std::uint64_t>(bytes_[offset_++]) << shift;
        return value;
    }
    std::vector<std::uint8_t> bytes(const char* label) {
        const auto length = u64(label);
        if (length > max_field_bytes) throw std::length_error("serialized field is unreasonable");
        if (length > bytes_.size() - offset_) throw std::invalid_argument(label);
        const auto begin = bytes_.begin() + static_cast<std::ptrdiff_t>(offset_);
        std::vector<std::uint8_t> result(begin, begin + static_cast<std::ptrdiff_t>(length));
        offset_ += static_cast<std::size_t>(length);
        return result;
    }
    std::string text(const char* label) {
        const auto raw = bytes(label);
        return std::string(raw.begin(), raw.end());
    }
    void end() const {
        if (offset_ != bytes_.size()) throw std::invalid_argument("trailing serialization bytes");
    }

private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t offset_ = 0;
};

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() > std::numeric_limits<std::uint64_t>::max()) {
        throw std::length_error("encoding is too large");
    }
    append_u64(output, static_cast<std::uint64_t>(bytes.size()));
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_text(std::vector<std::uint8_t>& output, std::string_view text) {
    append_u64(output, text.size());
    output.insert(output.end(), text.begin(), text.end());
}

void append_public_key(std::vector<std::uint8_t>& output, const AccountPublicKey& key) {
    append_text(output, key.user_id);
    append_text(output, key.account_id);
    append_bytes(output, key.u_i.to_bytes());
    append_bytes(output, key.y_i.to_bytes());
    append_bytes(output, key.member.to_bytes());
}

void append_version(std::vector<std::uint8_t>& output, std::string_view name) {
    static constexpr std::uint8_t version = 1;
    append_bytes(output, {version});
    append_text(output, name);
}

} // namespace

std::vector<std::uint8_t> encode_ring_label(const RingLabel& label) {
    std::vector<std::uint8_t> output;
    append_version(output, "lktrs/ring-label");
    append_text(output, label.issue);
    append_u64(output, label.accounts.size());
    for (const auto& key : label.accounts) append_public_key(output, key);
    return output;
}

RingLabel decode_ring_label(const crypto::PairingContext& pairing,
                            const crypto::DdhContext& ddh,
                            const std::vector<std::uint8_t>& bytes) {
    Reader reader(bytes);
    const auto version = reader.bytes("missing encoding version");
    if (version != std::vector<std::uint8_t>{1}) throw std::invalid_argument("unsupported ring encoding version");
    if (reader.text("missing encoding name") != "lktrs/ring-label") {
        throw std::invalid_argument("wrong ring encoding domain");
    }
    RingLabel result;
    result.issue = reader.text("missing ring issue");
    const auto count = reader.u64("missing ring account count");
    if (count > 100000) throw std::length_error("ring account count is unreasonable");
    result.accounts.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        const auto user_id = reader.text("missing account user id");
        const auto account_id = reader.text("missing account id");
        auto u_i = crypto::Gp::from_bytes(ddh, reader.bytes("missing account u_i"));
        auto y_i = crypto::Gp::from_bytes(ddh, reader.bytes("missing account y_i"));
        auto member = crypto::Scalar::from_bytes(pairing, reader.bytes("missing account member"));
        AccountPublicKey key{user_id, account_id, std::move(u_i), std::move(y_i), std::move(member)};
        result.accounts.push_back(std::move(key));
    }
    reader.end();
    return result;
}

std::vector<std::uint8_t> encode_challenge_transcript(const RingLabel& label,
                                                       std::string_view message,
                                                       const crypto::G1& nym,
                                                       std::uint64_t timestamp) {
    std::vector<std::uint8_t> output;
    append_version(output, "lktrs/challenge");
    const auto ring = encode_ring_label(label);
    append_bytes(output, ring);
    append_text(output, message);
    append_bytes(output, nym.to_bytes());
    append_u64(output, timestamp);
    return output;
}

std::vector<std::uint8_t> encode_public_signature(const ClearSignature& signature) {
    std::vector<std::uint8_t> output;
    append_version(output, "lktrs/clear-signature");
    append_bytes(output, signature.nym.to_bytes());
    append_bytes(output, signature.accumulator_value.to_bytes());
    append_bytes(output, signature.one_time_pass.to_bytes());
    append_bytes(output, signature.trace_tag.to_bytes());
    append_bytes(output, signature.challenge.to_bytes());
    append_u64(output, signature.timestamp);
    return output;
}

PublicSignature decode_public_signature(const crypto::PairingContext& pairing,
                                        const crypto::DdhContext& ddh,
                                        const std::vector<std::uint8_t>& bytes) {
    Reader reader(bytes);
    const auto version = reader.bytes("missing signature encoding version");
    if (version != std::vector<std::uint8_t>{1}) throw std::invalid_argument("unsupported signature encoding version");
    if (reader.text("missing signature encoding name") != "lktrs/clear-signature") {
        throw std::invalid_argument("wrong signature encoding domain");
    }
    PublicSignature result{
        crypto::G1::from_bytes(pairing, reader.bytes("missing signature nym")),
        crypto::G1::from_bytes(pairing, reader.bytes("missing accumulator value")),
        crypto::Gp::from_bytes(ddh, reader.bytes("missing one-time pass")),
        crypto::Gp::from_bytes(ddh, reader.bytes("missing trace tag")),
        crypto::Scalar::from_bytes(pairing, reader.bytes("missing challenge")),
        reader.u64("missing signature timestamp")};
    reader.end();
    return result;
}

} // namespace lktrs::protocol
