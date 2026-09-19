#include "lktrs/protocol/accumulator.hpp"

#include "lktrs/crypto/sha256.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <iterator>
#include <utility>

namespace lktrs::protocol {
namespace {

using crypto::add;
using crypto::mul;
using crypto::pair;
using crypto::pow;
using crypto::scalar;

template<class Group>
Group sample_nonidentity(const PairingContext& context) {
    for (int attempt = 0; attempt < 64; ++attempt) {
        auto candidate = Group::sample_for_testing(context);
        if (!candidate.is_identity()) return candidate;
    }
    throw std::runtime_error("could not sample a non-identity pairing element");
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::array<std::uint8_t, 32> set_digest(const std::vector<Scalar>& handles) {
    std::vector<std::vector<std::uint8_t>> encoded;
    encoded.reserve(handles.size());
    for (const auto& handle : handles) encoded.push_back(handle.to_bytes());
    std::sort(encoded.begin(), encoded.end());

    std::vector<std::uint8_t> transcript;
    static constexpr std::uint8_t domain[] = {
        'l', 'k', 't', 'r', 's', '/', 'a', 'c', 'c', 'u', 'm', 'u', 'l', 'a', 't', 'o', 'r', '/', 'v', '1'};
    transcript.insert(transcript.end(), std::begin(domain), std::end(domain));
    append_u64(transcript, encoded.size());
    for (const auto& bytes : encoded) {
        append_u64(transcript, bytes.size());
        transcript.insert(transcript.end(), bytes.begin(), bytes.end());
    }
    return crypto::sha256(transcript);
}

} // namespace

AccumulatorParameters::AccumulatorParameters(PairingContext context, G1 generator,
                                               G2 pairing_base, std::vector<G1> sdh,
                                               G2 h_tau)
    : context_(std::move(context)), generator_(std::move(generator)),
      pairing_base_(std::move(pairing_base)), sdh_(std::move(sdh)),
      h_tau_(std::move(h_tau)), ownership_(std::make_shared<OwnershipTag>()) {
    if (sdh_.empty()) throw std::invalid_argument("q-SDH tuple must contain g");
    if (generator_.is_identity() || pairing_base_.is_identity() || h_tau_.is_identity()) {
        throw std::invalid_argument("q-SDH parameters must be non-identity elements");
    }
    if (!sdh_.front().equals(generator_)) {
        throw std::invalid_argument("q-SDH tuple does not start with its generator");
    }
    // Trigger the typed wrapper's context checks at construction time instead
    // of deferring a mismatched public tuple until the first update.
    for (const auto& term : sdh_) {
        (void)term.mul(generator_);
    }
    (void)pair(generator_, pairing_base_);
    (void)pair(generator_, h_tau_);
    for (std::size_t index = 1; index < sdh_.size(); ++index) {
        if (!pair(sdh_[index], pairing_base_).equals(
                pair(sdh_[index - 1], h_tau_))) {
            throw std::invalid_argument("q-SDH public powers are inconsistent");
        }
    }
}

AccumulatorParameters AccumulatorParameters::for_testing(const PairingContext& context,
                                                         std::size_t max_members) {
    if (max_members == 0 || max_members == std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument("max_members is outside the supported range");
    }
    const auto generator = sample_nonidentity<G1>(context);
    const auto pairing_base = sample_nonidentity<G2>(context);

    std::vector<std::uint8_t> message;
    const auto parameter_id = context.parameter_id();
    message.insert(message.end(), parameter_id.begin(), parameter_id.end());
    append_u64(message, max_members);
    const auto tau = Scalar::hash_to_scalar(context, "lktrs/accumulator/testing-tau", message);

    std::vector<G1> sdh;
    sdh.reserve(max_members + 1);
    sdh.push_back(generator);
    for (std::size_t index = 1; index <= max_members; ++index) {
        sdh.push_back(pow(sdh.back(), tau));
    }
    // tau is a local setup value and is no longer reachable after return.
    auto h_tau = pow(pairing_base, tau);
    return AccumulatorParameters(context, generator, pairing_base, std::move(sdh),
                                 std::move(h_tau));
}

Accumulator::Snapshot::Snapshot(G1 value, std::uint64_t version,
                                std::array<std::uint8_t, 32> set_id)
    : value_(std::move(value)), version_(version), set_id_(set_id) {}

Accumulator::Accumulator(AccumulatorParameters parameters)
    : parameters_(std::move(parameters)), value_(parameters_.generator()) {
    set_id_ = digest({});
}

bool Accumulator::contains(const Scalar& handle) const {
    try {
        return std::any_of(members_.begin(), members_.end(),
                           [&handle](const Scalar& member) { return member.equals(handle); });
    } catch (const std::exception&) {
        return false;
    }
}

Accumulator::Snapshot Accumulator::snapshot() const {
    return Snapshot(value_, version_, set_id_);
}

G1 Accumulator::value_for(const std::vector<Scalar>& handles) const {
    std::vector<Scalar> candidate;
    candidate.reserve(handles.size());
    for (const auto& handle : handles) {
        if (std::any_of(candidate.begin(), candidate.end(),
                        [&handle](const Scalar& member) { return member.equals(handle); })) {
            throw std::invalid_argument("duplicate q-SDH member handle");
        }
        candidate.push_back(handle);
    }
    return accumulate(candidate);
}

G1 Accumulator::accumulate(const std::vector<Scalar>& handles) const {
    if (handles.size() > parameters_.max_members()) {
        throw std::length_error("set exceeds q-SDH tuple degree");
    }

    // The product polynomial is prod_i (X + a_i).  Its coefficients are
    // evaluated against g^(tau^i), so tau is never required by this operation.
    std::vector<Scalar> coefficients{scalar(context_copy(), 1)};
    for (const auto& handle : handles) {
        std::vector<Scalar> next(coefficients.size() + 1,
                                 scalar(context_copy(), 0));
        for (std::size_t index = 0; index < coefficients.size(); ++index) {
            next[index] = add(next[index], mul(coefficients[index], handle));
            next[index + 1] = add(next[index + 1], coefficients[index]);
        }
        coefficients = std::move(next);
    }

    G1 result(context_copy());
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        result = result.mul(pow(parameters_.sdh_[index], coefficients[index]));
    }
    if (result.is_identity()) {
        // A zero product means some a_i == -tau.  The public tuple cannot tell
        // us which factor caused it; accepting an identity accumulator would
        // make every membership equation degenerate, so fail closed.
        throw std::domain_error("q-SDH member factor is zero");
    }
    return result;
}

std::array<std::uint8_t, 32> Accumulator::digest(const std::vector<Scalar>& handles) const {
    return set_digest(handles);
}

Accumulator::Snapshot Accumulator::commit(std::vector<Scalar> handles, G1 value,
                                          std::array<std::uint8_t, 32> set_id) {
    if (version_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("accumulator version exhausted");
    }
    members_ = std::move(handles);
    value_ = std::move(value);
    set_id_ = set_id;
    ++version_;
    return snapshot();
}

Accumulator::Snapshot Accumulator::update(const std::vector<Scalar>& handles) {
    std::vector<Scalar> candidate;
    candidate.reserve(handles.size());
    for (const auto& handle : handles) {
        if (std::any_of(candidate.begin(), candidate.end(),
                        [&handle](const Scalar& member) { return member.equals(handle); })) {
            throw std::invalid_argument("duplicate q-SDH member handle");
        }
        candidate.push_back(handle);
    }
    auto candidate_value = accumulate(candidate);
    return commit(std::move(candidate), std::move(candidate_value), digest(handles));
}

Accumulator::Snapshot Accumulator::join(const Scalar& handle) {
    if (contains(handle)) throw std::invalid_argument("q-SDH member handle already joined");
    auto candidate = members_;
    candidate.push_back(handle);
    return update(candidate);
}

Accumulator::Snapshot Accumulator::exit(const Scalar& handle) {
    const auto found = std::find_if(members_.begin(), members_.end(),
                                    [&handle](const Scalar& member) { return member.equals(handle); });
    if (found == members_.end()) throw std::invalid_argument("q-SDH member handle is not joined");
    std::vector<Scalar> candidate;
    candidate.reserve(members_.size() - 1);
    for (const auto& member : members_) {
        if (!member.equals(handle)) candidate.push_back(member);
    }
    // An empty set is represented by the generator, not by the group identity.
    // `accumulate` handles that convention and still validates all factors.
    return update(candidate);
}

G1 Accumulator::witness_value(const Scalar& handle) const {
    if (!contains(handle)) throw std::invalid_argument("cannot witness a non-member handle");
    std::vector<Scalar> others;
    others.reserve(members_.size() - 1);
    bool removed = false;
    for (const auto& member : members_) {
        if (!removed && member.equals(handle)) {
            removed = true;
            continue;
        }
        others.push_back(member);
    }
    return accumulate(others);
}

Accumulator::MembershipWitness Accumulator::witness(const Scalar& handle) const {
    return MembershipWitness(handle, witness_value(handle), version_, set_id_,
                             parameters_.ownership_);
}

bool Accumulator::verify(const Scalar& handle, const G1& witness_value_input) const {
    try {
        // e(w, h^(a+tau)) = e(V,h), with h^(a+tau) assembled from public h^tau.
        const auto member_term = pow(parameters_.pairing_base(), handle)
                                     .mul(parameters_.h_tau());
        return pair(witness_value_input, member_term).equals(
            pair(value_, parameters_.pairing_base()));
    } catch (const std::exception&) {
        // A malformed element or an independently-owned context is a failed
        // proof, never an exception that callers can accidentally ignore.
        return false;
    }
}

bool Accumulator::verify(const Scalar& handle, const MembershipWitness& witness_input) const {
    try {
        if (witness_input.owner_.get() != parameters_.ownership_.get() ||
            witness_input.version_ != version_ || witness_input.set_id_ != set_id_ ||
            !witness_input.handle_.equals(handle)) {
            return false;
        }
    } catch (const std::exception&) {
        return false;
    }
    return verify(handle, witness_input.value_);
}

} // namespace lktrs::protocol
