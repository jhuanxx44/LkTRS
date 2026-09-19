#include "lktrs/crypto/ddh.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace lktrs::crypto;

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Error, class F>
void rejects(F&& operation) {
    try {
        operation();
    } catch (const Error&) {
        return;
    }
    throw std::runtime_error("expected operation to reject");
}

void run() {
    const auto context = DdhContext::ristretto255("ddh-resource-test");
    require(context.scalar_order_bits() == 253, "unexpected Ristretto scalar order size");
    require(context.scalar_order_bytes() == 32, "unexpected Ristretto scalar encoding size");
    require(context.parameter_id() == "ddh-resource-test", "context id was not retained");

    const auto one = scalar(context, 1);
    const auto two = scalar(context, 2);
    const auto three = scalar(context, 3);
    require(add(one, two).equals(three), "scalar addition failed");
    require(sub(three, one).equals(two), "scalar subtraction failed");
    require(mul(two, three).equals(scalar(context, 6)), "scalar multiplication failed");
    require(inverse(three).mul(three).equals(one), "scalar inverse failed");
    require(scalar(context, -1).mul(scalar(context, -1)).equals(one),
            "signed scalar reduction failed");
    rejects<std::domain_error>([&] { (void)inverse(scalar(context, 0)); });

    const auto scalar_encoding = three.to_bytes();
    require(scalar_encoding.size() == 32, "scalar encoding width changed");
    require(GpScalar::from_bytes(context, scalar_encoding).equals(three),
            "scalar encoding did not round trip");
    rejects<std::invalid_argument>([&] {
        (void)GpScalar::from_bytes(context, std::vector<std::uint8_t>(31, 0));
    });
    rejects<std::invalid_argument>([&] {
        (void)GpScalar::from_bytes(context, std::vector<std::uint8_t>(32, 0xff));
    });

    const auto generator = gp_generator(context);
    require(!generator.is_identity(), "Ristretto generator is the identity");
    require(pow(generator, one).equals(generator), "generator exponentiation failed");
    require(pow(generator, scalar(context, 0)).is_identity(), "zero exponent failed");
    require(generator.mul(generator.inverse()).is_identity(), "group inverse failed");
    require(Gp(context).inverse().is_identity(), "identity inverse failed");
    auto moved_group_source = generator;
    auto moved_group = std::move(moved_group_source);
    require(!moved_group_source.has_value() && moved_group.equals(generator),
            "group move did not transfer ownership");
    rejects<std::logic_error>([&] { (void)moved_group_source.equals(moved_group); });
    rejects<std::logic_error>([&] { (void)moved_group_source.byte_length(); });

    auto moved_scalar_source = three;
    auto moved_scalar = std::move(moved_scalar_source);
    require(!moved_scalar_source.has_value() && moved_scalar.equals(three),
            "scalar move did not transfer ownership");
    rejects<std::logic_error>([&] { (void)moved_scalar_source.equals(moved_scalar); });
    rejects<std::logic_error>([&] { (void)moved_scalar_source.byte_length(); });

    const auto random_group = Gp::sample_for_testing(context);
    require(Gp::from_bytes(context, random_group.to_bytes()).equals(random_group),
            "Ristretto point encoding did not round trip");
    const auto identity_encoding = Gp(context).to_bytes();
    require(Gp::from_bytes(context, identity_encoding).is_identity(),
            "Ristretto identity encoding did not round trip");
    auto malformed = random_group.to_bytes();
    bool found_rejected = false;
    for (std::size_t index = 0; index < malformed.size() && !found_rejected; ++index) {
        malformed[index] ^= 0xff;
        try {
            (void)Gp::from_bytes(context, malformed);
        } catch (const std::invalid_argument&) {
            found_rejected = true;
        }
        malformed[index] ^= 0xff;
    }
    require(found_rejected, "point decoder accepted no malformed mutation");

    const auto a = GpScalar::sample_nonzero(context);
    const auto b = GpScalar::sample_nonzero(context);
    const auto left = pow(generator.mul(random_group), a);
    const auto right = pow(generator, a).mul(pow(random_group, a));
    require(left.equals(right), "Ristretto scalar multiplication is not distributive");
    require(pow(pow(generator, a), b).equals(pow(generator, a.mul(b))),
            "Ristretto exponent composition failed");

    const std::vector<std::uint8_t> message{'i', 's', 's', 'u', 'e'};
    const auto ut = Gp::hash_to_group(context, "lktrs/Gp/issue", message);
    require(!ut.is_identity(), "hash-to-group produced the identity");
    require(ut.equals(Gp::hash_to_group(context, "lktrs/Gp/issue", message)),
            "hash-to-group is not deterministic");
    require(!ut.equals(Gp::hash_to_group(context, "lktrs/Gp/other", message)),
            "hash-to-group ignored domain separation");
    const auto hs = GpScalar::hash_to_scalar(context, "lktrs/Gp/scalar", message);
    require(!hs.is_zero(), "hash-to-scalar produced zero");
    require(hs.equals(GpScalar::hash_to_scalar(context, "lktrs/Gp/scalar", message)),
            "hash-to-scalar is not deterministic");

    auto other_context = DdhContext::ristretto255("ddh-resource-other");
    auto other_scalar = scalar(other_context, 1);
    rejects<std::invalid_argument>([&] { (void)one.equals(other_scalar); });
    rejects<std::invalid_argument>([&] { (void)generator.equals(gp_generator(other_context)); });
    rejects<std::invalid_argument>([&] { (void)pow(generator, other_scalar); });

    std::cout << "PASS: standalone Ristretto255 DDH group and scalar backend\n";
}
} // namespace

int main() {
    try {
        run();
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
