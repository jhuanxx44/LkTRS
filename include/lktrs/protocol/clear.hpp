#pragma once

#include "lktrs/crypto/ddh.hpp"
#include "lktrs/crypto/pairing.hpp"
#include "lktrs/protocol/accumulator.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lktrs::protocol {

// The clear path is an executable reference model for the frozen equations.
// It intentionally carries the witness in ClearSignature and is therefore not
// anonymous.  Production signing must replace this disclosure with a
// ProofBackend (the Groth16 integration is tracked separately).
class Parameters final {
public:
    static Parameters for_testing(crypto::PairingContext pairing,
                                  crypto::DdhContext ddh,
                                  std::string issue,
                                  std::uint64_t k,
                                  std::size_t max_members);

    const crypto::PairingContext& pairing() const noexcept { return pairing_; }
    const crypto::DdhContext& ddh() const noexcept { return ddh_; }
    const std::string& issue() const noexcept { return issue_; }
    std::uint64_t limit() const noexcept { return k_; }
    const crypto::G1& g0() const noexcept { return g0_; }
    const crypto::G1& g1() const noexcept { return g1_; }
    const crypto::G1& g2() const noexcept { return g2_; }
    const crypto::Gp& u() const noexcept { return u_; }
    const crypto::Gp& u_t() const noexcept { return u_t_; }
    const AccumulatorParameters& accumulator_parameters() const noexcept { return accumulator_parameters_; }

private:
    Parameters(crypto::PairingContext pairing, crypto::DdhContext ddh,
                std::string issue, std::uint64_t k,
                crypto::G1 g0, crypto::G1 g1, crypto::G1 g2,
                crypto::Gp u, crypto::Gp u_t,
                AccumulatorParameters accumulator_parameters);

    crypto::PairingContext pairing_;
    crypto::DdhContext ddh_;
    std::string issue_;
    std::uint64_t k_;
    crypto::G1 g0_;
    crypto::G1 g1_;
    crypto::G1 g2_;
    crypto::Gp u_;
    crypto::Gp u_t_;
    AccumulatorParameters accumulator_parameters_;
};

struct UserSecret final {
    std::vector<std::uint8_t> seed;
};

struct AccountPublicKey final {
    std::string user_id;
    std::string account_id;
    crypto::Gp u_i;
    crypto::Gp y_i;
    crypto::Scalar member;
};

struct AccountSecret final {
    AccountPublicKey public_key;
    crypto::GpScalar d_i;
};

struct RingLabel final {
    std::string issue;
    std::vector<AccountPublicKey> accounts;
};

struct ClearWitness final {
    crypto::Scalar x_pair;
    crypto::Scalar s_pair;
    crypto::Scalar t_pair;
    crypto::GpScalar x_gp;
    crypto::GpScalar s_gp;
    crypto::GpScalar t_gp;
    crypto::GpScalar d_i;
    crypto::Scalar member;
    crypto::Scalar counter;
    crypto::G1 membership_witness;
};

struct ClearSignature final {
    crypto::G1 nym;
    crypto::G1 accumulator_value;
    crypto::Gp one_time_pass;
    crypto::Gp trace_tag;
    crypto::Scalar challenge;
    std::uint64_t timestamp = 0;
    ClearWitness witness;
};

enum class TraceKind { legal, traced, replay, invalid };
struct TraceResult final {
    TraceKind kind = TraceKind::invalid;
    std::string user_id;
};

class ClearProtocol final {
public:
    explicit ClearProtocol(Parameters parameters);

    const Parameters& parameters() const noexcept { return parameters_; }
    const Accumulator& accumulator() const noexcept { return accumulator_; }

    UserSecret create_user(std::string user_id);
    AccountSecret create_account(const std::string& user_id, std::string account_id);
    void join(const std::string& account_id);
    void exit(const std::string& account_id);
    // User-level revocation is the explicit exit of every active account owned
    // by the user, matching the frozen multi-account semantics.
    void revoke_user(const std::string& user_id);

    RingLabel current_label() const;
    ClearSignature sign_clear(const std::string& user_id,
                              const std::string& account_id,
                              std::string_view message,
                              std::uint64_t timestamp);
    bool verify_clear(const RingLabel&, std::string_view message,
                      const ClearSignature&) const;
    bool link_clear(const RingLabel&, std::string_view message1,
                    const ClearSignature&, std::string_view message2,
                    const ClearSignature&) const;
    TraceResult trace_clear(const RingLabel&, std::string_view message1,
                            const ClearSignature&, std::string_view message2,
                            const ClearSignature&) const;

private:
    struct UserRecord final {
        UserSecret secret;
        crypto::Scalar x_pair;
        crypto::GpScalar x_gp;
        crypto::Scalar s_pair;
        crypto::Scalar t_pair;
        crypto::GpScalar s_gp;
        crypto::GpScalar t_gp;
        std::uint64_t next_counter = 0;
    };
    struct AccountRecord final {
        AccountSecret secret;
        bool active = false;
    };

    Parameters parameters_;
    Accumulator accumulator_;
    std::unordered_map<std::string, UserRecord> users_;
    std::unordered_map<std::string, AccountRecord> accounts_;
    std::unordered_set<std::string> revoked_users_;

    const UserRecord& user(const std::string&) const;
    UserRecord& user(const std::string&);
    const AccountRecord& account(const std::string&) const;
    AccountRecord& account(const std::string&);
    crypto::Scalar challenge(const RingLabel&, std::string_view,
                             const crypto::G1&, std::uint64_t) const;
    crypto::GpScalar gp_challenge(const crypto::Scalar&) const;
    std::vector<crypto::Scalar> active_handles() const;
};

} // namespace lktrs::protocol
