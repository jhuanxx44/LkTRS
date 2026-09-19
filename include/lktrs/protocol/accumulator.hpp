#pragma once

#include "lktrs/crypto/pairing.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace lktrs::protocol {

using crypto::G1;
using crypto::G2;
using crypto::PairingContext;
using crypto::Scalar;

// Public parameters for the trapdoor-restored q-SDH accumulator.  `sdh` is
// (g, g^tau, ..., g^(tau^q)); tau itself is intentionally not represented.
// `h_tau` is h^tau, which is needed to form h^(a+tau) during verification.
class AccumulatorParameters final {
public:
    // Construct from a public setup transcript.  `sdh.size() - 1` is the
    // maximum supported set cardinality.  The constructor rejects an empty
    // tuple, an identity base, and an identity h^tau because those would not
    // describe a usable non-zero-trapdoor instance.
    AccumulatorParameters(PairingContext context, G1 generator, G2 pairing_base,
                          std::vector<G1> sdh, G2 h_tau);

    // Test/measurement setup only.  The helper samples a non-identity base,
    // derives a non-zero tau, materializes the public tuple, then drops tau.
    // It is not a deployment ceremony or an entropy policy.
    static AccumulatorParameters for_testing(const PairingContext&, std::size_t max_members);

    const PairingContext& context() const noexcept { return context_; }
    const G1& generator() const noexcept { return generator_; }
    const G2& pairing_base() const noexcept { return pairing_base_; }
    const G2& h_tau() const noexcept { return h_tau_; }
    const std::vector<G1>& sdh() const noexcept { return sdh_; }
    std::size_t max_members() const noexcept { return sdh_.size() - 1; }

private:
    struct OwnershipTag {};

    PairingContext context_;
    G1 generator_;
    G2 pairing_base_;
    std::vector<G1> sdh_;
    G2 h_tau_;
    // Equality of this token, in addition to the version and set digest,
    // prevents a witness from one independently-created parameter object from
    // being accepted accidentally when the serialized values happen to match.
    std::shared_ptr<const OwnershipTag> ownership_;

    friend class Accumulator;
};

class Accumulator final {
public:
    struct Snapshot final {
        Snapshot(G1 value, std::uint64_t version, std::array<std::uint8_t, 32> set_id);

        const G1& value() const noexcept { return value_; }
        std::uint64_t version() const noexcept { return version_; }
        const std::array<std::uint8_t, 32>& set_id() const noexcept { return set_id_; }

    private:
        G1 value_;
        std::uint64_t version_;
        std::array<std::uint8_t, 32> set_id_;
    };

    struct MembershipWitness final {
        const Scalar& handle() const noexcept { return handle_; }
        const G1& value() const noexcept { return value_; }
        std::uint64_t version() const noexcept { return version_; }
        const std::array<std::uint8_t, 32>& set_id() const noexcept { return set_id_; }

    private:
        MembershipWitness(Scalar handle, G1 value, std::uint64_t version,
                          std::array<std::uint8_t, 32> set_id,
                          std::shared_ptr<const AccumulatorParameters::OwnershipTag> owner)
            : handle_(std::move(handle)), value_(std::move(value)), version_(version),
              set_id_(set_id), owner_(std::move(owner)) {}

        Scalar handle_;
        G1 value_;
        std::uint64_t version_;
        std::array<std::uint8_t, 32> set_id_;
        std::shared_ptr<const AccumulatorParameters::OwnershipTag> owner_;

        friend class Accumulator;
    };

    explicit Accumulator(AccumulatorParameters parameters);

    const AccumulatorParameters& parameters() const noexcept { return parameters_; }
    const G1& value() const noexcept { return value_; }
    std::uint64_t version() const noexcept { return version_; }
    std::size_t size() const noexcept { return members_.size(); }
    bool contains(const Scalar&) const;
    const std::array<std::uint8_t, 32>& set_id() const noexcept { return set_id_; }
    Snapshot snapshot() const;

    // Recompute the public accumulator value for a candidate set without
    // mutating this state.  Callers use this when validating a signature's
    // ring label against its carried snapshot.
    G1 value_for(const std::vector<Scalar>& handles) const;

    // Mutations are account-handle operations.  They reject duplicates,
    // unknown exits, and a set whose size exceeds the published q-SDH tuple.
    // A successful mutation increments the version and invalidates old
    // MembershipWitness objects, even when their algebraic relation would
    // otherwise remain true.
    Snapshot join(const Scalar& handle);
    Snapshot exit(const Scalar& handle);
    Snapshot update(const std::vector<Scalar>& handles);

    MembershipWitness witness(const Scalar& handle) const;

    // Verify against the current accumulator value.  This overload is useful
    // for checking raw proof material and deliberately has no metadata to
    // authorize a stale witness.
    bool verify(const Scalar& handle, const G1& witness_value) const;

    // Verify a witness produced by this state.  Version, set digest, and
    // parameter ownership are checked before the pairing relation.
    bool verify(const Scalar& handle, const MembershipWitness&) const;

private:
    PairingContext context_copy() const { return parameters_.context_; }
    G1 accumulate(const std::vector<Scalar>& handles) const;
    G1 witness_value(const Scalar& handle) const;
    std::array<std::uint8_t, 32> digest(const std::vector<Scalar>& handles) const;
    Snapshot commit(std::vector<Scalar> handles, G1 value,
                    std::array<std::uint8_t, 32> set_id);

    AccumulatorParameters parameters_;
    G1 value_;
    std::vector<Scalar> members_;
    std::uint64_t version_ = 0;
    std::array<std::uint8_t, 32> set_id_{};
};

} // namespace lktrs::protocol
