#include "lktrs/protocol/accumulator.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

using lktrs::crypto::PairingContext;
using lktrs::crypto::inverse;
using lktrs::crypto::pow;
using lktrs::crypto::scalar;
using lktrs::protocol::Accumulator;
using lktrs::protocol::AccumulatorParameters;

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Error, class Function>
void rejects(Function&& function) {
    try {
        function();
    } catch (const Error&) {
        return;
    }
    throw std::runtime_error("operation unexpectedly succeeded");
}

PairingContext context(const std::string& path) {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("could not read parameter fixture");
    const std::string parameters{std::istreambuf_iterator<char>(input), {}};
    return PairingContext::from_trusted_parameters("accumulator-test", parameters);
}

void run(const std::string& path) {
    auto ctx = context(path);
    auto parameters = AccumulatorParameters::for_testing(ctx, 8);
    Accumulator accumulator(parameters);
    auto bad_powers = parameters.sdh();
    bad_powers[1] = bad_powers[0];
    rejects<std::invalid_argument>([&] {
        (void)AccumulatorParameters(ctx, parameters.generator(), parameters.pairing_base(),
                                     bad_powers, parameters.h_tau());
    });

    const auto a = scalar(ctx, 3);
    const auto b = scalar(ctx, 5);
    const auto c = scalar(ctx, 7);
    const auto outsider = scalar(ctx, 11);

    require(accumulator.version() == 0, "empty accumulator version is not zero");
    require(accumulator.size() == 0, "empty accumulator has members");
    require(accumulator.value().equals(parameters.generator()),
            "empty q-SDH accumulator is not its generator");

    accumulator.join(a);
    const auto first = accumulator.witness(a);
    require(accumulator.verify(a, first), "single-member witness does not verify");
    require(accumulator.verify(a, first.value()), "raw single-member witness does not verify");

    accumulator.join(b);
    accumulator.join(c);
    require(accumulator.size() == 3, "join did not add all members");
    require(accumulator.verify(a, accumulator.witness(a)), "member a witness failed");
    require(accumulator.verify(b, accumulator.witness(b)), "member b witness failed");
    require(accumulator.verify(c, accumulator.witness(c)), "member c witness failed");
    rejects<std::invalid_argument>([&] { accumulator.join(a); });
    rejects<std::invalid_argument>([&] { (void)accumulator.witness(outsider); });

    // E1 mutation: the old u^x accumulator permits V^(1/z) as a witness for
    // any outsider.  The non-zero-trapdoor q-SDH relation must reject it.
    const auto forged = pow(accumulator.value(), inverse(outsider));
    require(!accumulator.verify(outsider, forged),
            "old u^x exponent-inversion forgery was accepted");

    const auto stale = accumulator.witness(a);
    const auto old_value = stale.value();
    const auto old_version = stale.version();
    accumulator.exit(c);
    require(accumulator.version() > old_version, "exit did not advance the version");
    require(!accumulator.verify(a, stale), "stale witness survived exit update");
    require(!accumulator.verify(a, old_value),
            "old witness unexpectedly verifies against the new accumulator");
    require(accumulator.verify(a, accumulator.witness(a)),
            "remaining member did not verify after exit");
    require(!accumulator.contains(c), "exit did not remove the requested handle");
    rejects<std::invalid_argument>([&] { accumulator.exit(c); });

    // Witness metadata carries both state version and set ownership.  A
    // witness from an independently-created accumulator must fail closed even
    // when the public tuple and set values happen to be equal.
    auto independent_parameters = AccumulatorParameters::for_testing(ctx, 8);
    Accumulator independent(independent_parameters);
    independent.update({a, b});
    const auto independent_witness = independent.witness(a);
    require(!accumulator.verify(a, independent_witness),
            "witness from an independent accumulator was accepted");

    auto other_context = context(path);
    auto other_parameters = AccumulatorParameters::for_testing(other_context, 8);
    Accumulator other_accumulator(other_parameters);
    const auto other_a = scalar(other_context, 3);
    other_accumulator.join(other_a);
    const auto other_witness = other_accumulator.witness(other_a);
    require(!accumulator.verify(other_a, other_witness),
            "cross-context witness did not fail closed");

    accumulator.update({a, b});
    const auto before_update = accumulator.version();
    accumulator.update({b, a});
    require(accumulator.version() > before_update, "update did not advance version");
    require(accumulator.verify(a, accumulator.witness(a)),
            "set-order update broke membership");
    rejects<std::invalid_argument>([&] { accumulator.update({a, a}); });
    std::vector<lktrs::crypto::Scalar> oversized;
    for (long value = 100; value < 109; ++value) oversized.push_back(scalar(ctx, value));
    const auto before_oversized = accumulator.snapshot();
    rejects<std::length_error>([&] { accumulator.update(oversized); });
    require(accumulator.version() == before_oversized.version() &&
                accumulator.value().equals(before_oversized.value()),
            "oversized update changed accumulator state");
    std::cout << "PASS: q-SDH join/exit, ownership, stale witnesses, and E1 forgery rejection\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <pbc.param>\n";
        return 2;
    }
    try {
        run(argv[1]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
