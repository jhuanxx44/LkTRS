#include "lktrs/protocol/clear.hpp"
#include "lktrs/protocol/serialization.hpp"

#include "lktrs/crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <limits>
#include <stdexcept>
#include <utility>

namespace lktrs::protocol {
namespace {

using crypto::G1;
using crypto::Gp;
using crypto::GpScalar;
using crypto::PairingContext;
using crypto::Scalar;

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& value) {
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_text(std::vector<std::uint8_t>& output, std::string_view value) {
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

std::vector<std::uint8_t> seed_material(std::string_view domain,
                                        std::string_view user_id,
                                        const std::vector<std::uint8_t>& entropy) {
    std::vector<std::uint8_t> output;
    append_text(output, domain);
    append_text(output, user_id);
    append_bytes(output, entropy);
    return output;
}

std::vector<std::uint8_t> derive_material(const UserSecret& secret,
                                          std::string_view issue,
                                          std::string_view account_id,
                                          std::uint8_t branch) {
    std::vector<std::uint8_t> output;
    append_bytes(output, secret.seed);
    append_text(output, issue);
    append_text(output, account_id);
    output.push_back(branch);
    return output;
}

G1 sample_nonidentity_g1(const PairingContext& context) {
    for (int attempt = 0; attempt < 64; ++attempt) {
        auto candidate = G1::sample_for_testing(context);
        if (!candidate.is_identity()) return candidate;
    }
    throw std::runtime_error("could not sample a nonidentity G1 base");
}

std::uint64_t small_counter(const Scalar& value) {
    const auto bytes = value.to_bytes();
    if (bytes.size() > sizeof(std::uint64_t)) {
        const auto split = bytes.size() - sizeof(std::uint64_t);
        if (std::any_of(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(split),
                        [](std::uint8_t byte) { return byte != 0; })) {
            throw std::domain_error("counter does not fit the protocol counter width");
        }
    }
    std::uint64_t result = 0;
    const auto first = bytes.size() > sizeof(result) ? bytes.size() - sizeof(result) : 0;
    for (std::size_t index = first; index < bytes.size(); ++index) {
        result = (result << 8U) | bytes[index];
    }
    return result;
}

Scalar member_handle(const PairingContext& context, const AccountPublicKey& key) {
    std::vector<std::uint8_t> message;
    const auto u = key.u_i.to_bytes();
    const auto y = key.y_i.to_bytes();
    append_bytes(message, u);
    append_bytes(message, y);
    return Scalar::hash_to_scalar(context, "lktrs/member-handle/v1", message);
}

bool same_account(const AccountPublicKey& left, const AccountPublicKey& right) {
    return left.account_id == right.account_id && left.user_id == right.user_id &&
           left.u_i.equals(right.u_i) && left.y_i.equals(right.y_i) &&
           left.member.equals(right.member);
}

} // namespace

Parameters::Parameters(PairingContext pairing, crypto::DdhContext ddh,
                       std::string issue, std::uint64_t k,
                       G1 g0, G1 g1, G1 g2, Gp u, Gp u_t,
                       AccumulatorParameters accumulator_parameters)
    : pairing_(std::move(pairing)), ddh_(std::move(ddh)), issue_(std::move(issue)), k_(k),
      g0_(std::move(g0)), g1_(std::move(g1)), g2_(std::move(g2)), u_(std::move(u)),
      u_t_(std::move(u_t)), accumulator_parameters_(std::move(accumulator_parameters)) {
    if (issue_.empty() || k_ == 0) throw std::invalid_argument("invalid Lk-TRS issue or limit");
}

Parameters Parameters::for_testing(PairingContext pairing, crypto::DdhContext ddh,
                                   std::string issue, std::uint64_t k,
                                   std::size_t max_members) {
    if (issue.empty() || k == 0 || max_members == 0) {
        throw std::invalid_argument("invalid Lk-TRS setup parameters");
    }
    const auto g0 = sample_nonidentity_g1(pairing);
    const auto g1 = sample_nonidentity_g1(pairing);
    const auto g2 = sample_nonidentity_g1(pairing);
    const auto u = crypto::gp_generator(ddh);
    std::vector<std::uint8_t> issue_bytes(issue.begin(), issue.end());
    const auto u_t = crypto::hash_to_group_Gp(ddh, "lktrs/issue/v1", issue_bytes);
    auto accumulator_parameters = AccumulatorParameters::for_testing(pairing, max_members);
    return Parameters(std::move(pairing), std::move(ddh), std::move(issue), k,
                      g0, g1, g2, u, u_t, std::move(accumulator_parameters));
}

ClearProtocol::ClearProtocol(Parameters parameters)
    : parameters_(std::move(parameters)), accumulator_(parameters_.accumulator_parameters()) {}

const ClearProtocol::UserRecord& ClearProtocol::user(const std::string& user_id) const {
    const auto found = users_.find(user_id);
    if (found == users_.end()) throw std::invalid_argument("unknown Lk-TRS user");
    return found->second;
}

ClearProtocol::UserRecord& ClearProtocol::user(const std::string& user_id) {
    const auto found = users_.find(user_id);
    if (found == users_.end()) throw std::invalid_argument("unknown Lk-TRS user");
    return found->second;
}

const ClearProtocol::AccountRecord& ClearProtocol::account(const std::string& account_id) const {
    const auto found = accounts_.find(account_id);
    if (found == accounts_.end()) throw std::invalid_argument("unknown Lk-TRS account");
    return found->second;
}

ClearProtocol::AccountRecord& ClearProtocol::account(const std::string& account_id) {
    const auto found = accounts_.find(account_id);
    if (found == accounts_.end()) throw std::invalid_argument("unknown Lk-TRS account");
    return found->second;
}

UserSecret ClearProtocol::create_user(std::string user_id) {
    if (user_id.empty()) throw std::invalid_argument("user id cannot be empty");
    if (users_.find(user_id) != users_.end()) throw std::invalid_argument("duplicate user id");
    if (revoked_users_.count(user_id) != 0) throw std::invalid_argument("user is revoked");
    const auto entropy = Scalar::sample_for_testing(parameters_.pairing()).to_bytes();
    UserSecret secret;
    const auto seed_digest = crypto::sha256(seed_material("lktrs/user-seed/v1", user_id, entropy));
    secret.seed.assign(seed_digest.begin(), seed_digest.end());
    const auto x_pair = Scalar::hash_to_scalar(parameters_.pairing(), "lktrs/user-x/pair", secret.seed);
    const auto x_gp = GpScalar::hash_to_scalar(parameters_.ddh(), "lktrs/user-x/gp", secret.seed);
    const auto pair_material = derive_material(secret, parameters_.issue(), "", 0);
    const auto gp_material = pair_material;
    UserRecord record{
        secret,
        x_pair,
        x_gp,
        Scalar::hash_to_scalar(parameters_.pairing(), "lktrs/user-s/pair", pair_material),
        Scalar::hash_to_scalar(parameters_.pairing(), "lktrs/user-t/pair", derive_material(secret, parameters_.issue(), "", 1)),
        GpScalar::hash_to_scalar(parameters_.ddh(), "lktrs/user-s/gp", gp_material),
        GpScalar::hash_to_scalar(parameters_.ddh(), "lktrs/user-t/gp", derive_material(secret, parameters_.issue(), "", 1)),
        0};
    const auto inserted = users_.emplace(user_id, std::move(record));
    if (!inserted.second) throw std::logic_error("user insertion unexpectedly failed");
    return inserted.first->second.secret;
}

AccountSecret ClearProtocol::create_account(const std::string& user_id, std::string account_id) {
    if (account_id.empty()) throw std::invalid_argument("account id cannot be empty");
    if (accounts_.find(account_id) != accounts_.end()) throw std::invalid_argument("duplicate account id");
    const auto& owner = user(user_id);
    const auto material = derive_material(owner.secret, parameters_.issue(), account_id, 2);
    const auto d = GpScalar::hash_to_scalar(parameters_.ddh(), "lktrs/account-d/v1", material);
    const auto u_i = crypto::pow(parameters_.u(), d);
    const auto y_i = crypto::pow(u_i, owner.x_gp);
    AccountPublicKey public_key{user_id, account_id, u_i, y_i, Scalar(parameters_.pairing())};
    public_key.member = member_handle(parameters_.pairing(), public_key);
    AccountSecret result{public_key, d};
    accounts_.emplace(account_id, AccountRecord{result, false});
    return result;
}

void ClearProtocol::join(const std::string& account_id) {
    auto& record = account(account_id);
    if (revoked_users_.count(record.secret.public_key.user_id) != 0) {
        throw std::invalid_argument("user is revoked");
    }
    if (record.active) throw std::invalid_argument("account is already joined");
    accumulator_.join(record.secret.public_key.member);
    record.active = true;
}

void ClearProtocol::exit(const std::string& account_id) {
    auto& record = account(account_id);
    if (!record.active) throw std::invalid_argument("account is not joined");
    accumulator_.exit(record.secret.public_key.member);
    record.active = false;
}

void ClearProtocol::revoke_user(const std::string& user_id) {
    (void)user(user_id);
    revoked_users_.insert(user_id);
    std::vector<std::string> owned;
    for (const auto& [account_id, record] : accounts_) {
        if (record.active && record.secret.public_key.user_id == user_id) owned.push_back(account_id);
    }
    std::sort(owned.begin(), owned.end());
    for (const auto& account_id : owned) exit(account_id);
}

std::vector<Scalar> ClearProtocol::active_handles() const {
    std::vector<std::string> ids;
    for (const auto& [id, record] : accounts_) {
        if (record.active) ids.push_back(id);
    }
    std::sort(ids.begin(), ids.end());
    std::vector<Scalar> handles;
    handles.reserve(ids.size());
    for (const auto& id : ids) handles.push_back(accounts_.at(id).secret.public_key.member);
    return handles;
}

RingLabel ClearProtocol::current_label() const {
    RingLabel label;
    label.issue = parameters_.issue();
    std::vector<std::string> ids;
    for (const auto& [id, record] : accounts_) {
        if (record.active) ids.push_back(id);
    }
    std::sort(ids.begin(), ids.end());
    label.accounts.reserve(ids.size());
    for (const auto& id : ids) label.accounts.push_back(accounts_.at(id).secret.public_key);
    return label;
}

Scalar ClearProtocol::challenge(const RingLabel& label, std::string_view message,
                                const G1& nym, std::uint64_t timestamp) const {
    const auto transcript = encode_challenge_transcript(label, message, nym, timestamp);
    return Scalar::hash_to_scalar(parameters_.pairing(), "lktrs/challenge/v1", transcript);
}

GpScalar ClearProtocol::gp_challenge(const Scalar& challenge_value) const {
    return GpScalar::hash_to_scalar(parameters_.ddh(), "lktrs/challenge/gp/v1",
                                     challenge_value.to_bytes());
}

ClearSignature ClearProtocol::sign_clear(const std::string& user_id,
                                         const std::string& account_id,
                                         std::string_view message,
                                         std::uint64_t timestamp) {
    auto& owner = user(user_id);
    auto& account_record = account(account_id);
    if (account_record.secret.public_key.user_id != user_id) {
        throw std::invalid_argument("account belongs to a different user");
    }
    if (!account_record.active) throw std::invalid_argument("account is not joined");
    if (owner.next_counter >= parameters_.limit()) throw std::domain_error("k limit exhausted");
    if (owner.next_counter > static_cast<std::uint64_t>(LONG_MAX)) {
        throw std::overflow_error("counter is too large for the scalar adapter");
    }

    const auto member = account_record.secret.public_key.member;
    const auto membership = accumulator_.witness(member);
    const auto counter = scalar(parameters_.pairing(), static_cast<long>(owner.next_counter));
    const auto counter_gp = crypto::scalar(parameters_.ddh(), static_cast<long>(owner.next_counter));
    const auto one_pair = scalar(parameters_.pairing(), 1);
    const auto one_gp = crypto::scalar(parameters_.ddh(), 1);
    const auto s_denom = crypto::add(crypto::add(owner.s_gp, counter_gp), one_gp);
    const auto t_denom = crypto::add(crypto::add(owner.t_gp, counter_gp), one_gp);
    if (s_denom.is_zero() || t_denom.is_zero()) throw std::domain_error("invalid counter denominator");

    const auto nym = crypto::pow(parameters_.g0(), owner.s_pair)
                         .mul(crypto::pow(parameters_.g1(), owner.t_pair))
                         .mul(crypto::pow(parameters_.g2(), owner.x_pair));
    const auto challenge_value = challenge(current_label(), message, nym, timestamp);
    const auto challenge_gp = gp_challenge(challenge_value);
    const auto one_time_pass = crypto::pow(parameters_.u_t(), crypto::inverse(s_denom));
    const auto trace_tag = crypto::pow(parameters_.u(), owner.x_gp)
                               .mul(crypto::pow(parameters_.u_t(),
                                                 crypto::mul(challenge_gp, crypto::inverse(t_denom))));
    ClearWitness witness{owner.x_pair, owner.s_pair, owner.t_pair, owner.x_gp,
                         owner.s_gp, owner.t_gp, account_record.secret.d_i,
                         member, counter, membership.value()};
    ClearSignature result{nym, accumulator_.value(), one_time_pass, trace_tag,
                          challenge_value, timestamp, std::move(witness)};
    ++owner.next_counter;
    return result;
}

bool ClearProtocol::verify_clear(const RingLabel& label, std::string_view message,
                                 const ClearSignature& signature) const {
    try {
        if (label.issue != parameters_.issue() || label.accounts.empty()) return false;
        if (signature.challenge.equals(challenge(label, message, signature.nym, signature.timestamp)) == false) {
            return false;
        }
        const auto expected_value = accumulator_.value_for(active_handles());
        if (!signature.accumulator_value.equals(expected_value)) return false;
        const auto expected_label = current_label();
        if (label.accounts.size() != expected_label.accounts.size()) return false;
        for (std::size_t index = 0; index < label.accounts.size(); ++index) {
            if (!same_account(label.accounts[index], expected_label.accounts[index])) return false;
        }

        const auto counter_value = small_counter(signature.witness.counter);
        if (counter_value >= parameters_.limit()) return false;
        const auto found = std::find_if(label.accounts.begin(), label.accounts.end(),
                                        [&signature](const AccountPublicKey& key) {
                                            return key.member.equals(signature.witness.member);
                                        });
        if (found == label.accounts.end()) return false;
        const auto& record = account(found->account_id);
        if (!record.active || !same_account(record.secret.public_key, *found)) return false;

        const auto& owner = user(found->user_id);
        if (!signature.witness.x_pair.equals(owner.x_pair) ||
            !signature.witness.s_pair.equals(owner.s_pair) ||
            !signature.witness.t_pair.equals(owner.t_pair) ||
            !signature.witness.x_gp.equals(owner.x_gp) ||
            !signature.witness.s_gp.equals(owner.s_gp) ||
            !signature.witness.t_gp.equals(owner.t_gp)) return false;
        if (!signature.witness.member.equals(member_handle(parameters_.pairing(), *found))) return false;
        if (!crypto::pow(parameters_.u(), signature.witness.d_i).equals(found->u_i)) return false;
        if (!crypto::pow(found->u_i, signature.witness.x_gp).equals(found->y_i)) return false;
        if (!accumulator_.verify(signature.witness.member, signature.witness.membership_witness)) return false;

        const auto nym = crypto::pow(parameters_.g0(), signature.witness.s_pair)
                             .mul(crypto::pow(parameters_.g1(), signature.witness.t_pair))
                             .mul(crypto::pow(parameters_.g2(), signature.witness.x_pair));
        if (!signature.nym.equals(nym)) return false;
        const auto counter_gp = crypto::scalar(parameters_.ddh(), static_cast<long>(counter_value));
        const auto one_gp = crypto::scalar(parameters_.ddh(), 1);
        const auto s_denom = crypto::add(crypto::add(owner.s_gp, counter_gp), one_gp);
        const auto t_denom = crypto::add(crypto::add(owner.t_gp, counter_gp), one_gp);
        if (s_denom.is_zero() || t_denom.is_zero()) return false;
        const auto challenge_gp = gp_challenge(signature.challenge);
        if (!signature.one_time_pass.equals(crypto::pow(parameters_.u_t(), crypto::inverse(s_denom)))) return false;
        if (!signature.trace_tag.equals(
                crypto::pow(parameters_.u(), owner.x_gp).mul(
                    crypto::pow(parameters_.u_t(), crypto::mul(challenge_gp, crypto::inverse(t_denom)))))) {
            return false;
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ClearProtocol::link_clear(const RingLabel& label, std::string_view message1,
                               const ClearSignature& first, std::string_view message2,
                               const ClearSignature& second) const {
    return verify_clear(label, message1, first) && verify_clear(label, message2, second) &&
           first.nym.equals(second.nym);
}

TraceResult ClearProtocol::trace_clear(const RingLabel& label, std::string_view message1,
                                       const ClearSignature& first, std::string_view message2,
                                       const ClearSignature& second) const {
    TraceResult result;
    if (!verify_clear(label, message1, first) || !verify_clear(label, message2, second) ||
        !first.nym.equals(second.nym)) {
        return result;
    }
    if (!first.one_time_pass.equals(second.one_time_pass)) {
        result.kind = TraceKind::legal;
        return result;
    }
    if (first.challenge.equals(second.challenge) && first.trace_tag.equals(second.trace_tag) &&
        first.timestamp == second.timestamp) {
        result.kind = TraceKind::replay;
        return result;
    }
    const auto r1 = gp_challenge(first.challenge);
    const auto r2 = gp_challenge(second.challenge);
    const auto difference = crypto::sub(r2, r1);
    if (difference.is_zero()) return result;
    const auto numerator = crypto::pow(first.trace_tag, r2)
                               .mul(crypto::pow(second.trace_tag, r1).inverse());
    const auto recovered = crypto::pow(numerator, crypto::inverse(difference));
    for (const auto& [account_id, record] : accounts_) {
        if (!record.active) continue;
        if (crypto::pow(recovered, record.secret.d_i).equals(record.secret.public_key.y_i)) {
            result.kind = TraceKind::traced;
            result.user_id = record.secret.public_key.user_id;
            return result;
        }
    }
    return result;
}

} // namespace lktrs::protocol
