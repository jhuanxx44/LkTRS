#include "lktrs/crypto/ddh.hpp"
#include "lktrs/crypto/pairing.hpp"
#include "lktrs/protocol/clear.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

using namespace lktrs;

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
    throw std::runtime_error("expected operation to reject");
}

crypto::PairingContext pairing_from_file(const std::string& path) {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("could not read pairing fixture");
    const std::string parameters{std::istreambuf_iterator<char>(input), {}};
    return crypto::PairingContext::from_trusted_parameters("clear-protocol-test", parameters);
}

void run(const std::string& path) {
    auto pairing = pairing_from_file(path);
    auto ddh = crypto::DdhContext::ristretto255("clear-protocol-test-gp");
    auto parameters = protocol::Parameters::for_testing(
        std::move(pairing), std::move(ddh), "issue-1", 3, 8);
    protocol::ClearProtocol protocol(std::move(parameters));

    protocol.create_user("alice");
    protocol.create_user("bob");
    const auto alice_a = protocol.create_account("alice", "alice-a");
    const auto alice_b = protocol.create_account("alice", "alice-b");
    const auto bob_a = protocol.create_account("bob", "bob-a");
    require(!alice_a.public_key.member.equals(alice_b.public_key.member),
            "different accounts unexpectedly share a member handle");
    protocol.join(alice_a.public_key.account_id);
    protocol.join(alice_b.public_key.account_id);
    protocol.join(bob_a.public_key.account_id);

    const auto label = protocol.current_label();
    const auto first = protocol.sign_clear("alice", "alice-a", "m1", 100);
    const auto second = protocol.sign_clear("alice", "alice-b", "m2", 101);
    const auto bob = protocol.sign_clear("bob", "bob-a", "m3", 102);
    require(protocol.verify_clear(label, "m1", first), "first clear signature rejected");
    require(protocol.verify_clear(label, "m2", second), "second clear signature rejected");
    require(protocol.verify_clear(label, "m3", bob), "bob clear signature rejected");
    require(protocol.link_clear(label, "m1", first, "m2", second),
            "same-user signatures did not link");
    require(!protocol.link_clear(label, "m1", first, "m3", bob),
            "different-user signatures linked");
    require(protocol.trace_clear(label, "m1", first, "m2", second).kind ==
                protocol::TraceKind::legal,
            "different counters were not legal");
    require(protocol.trace_clear(label, "m1", first, "m1", first).kind ==
                protocol::TraceKind::replay,
            "exact replay was not classified as replay");

    auto tampered = first;
    tampered.trace_tag = bob.trace_tag;
    require(!protocol.verify_clear(label, "m1", tampered),
            "tampered trace tag was accepted");
    require(!protocol.verify_clear(label, "wrong-message", first),
            "message substitution was accepted");

    protocol.exit("alice-a");
    require(!protocol.verify_clear(label, "m1", first),
            "signature from an exited account remained valid in the current ring");
    const auto new_label = protocol.current_label();
    require(new_label.accounts.size() == 2, "exit did not shrink the ring");
    const auto after_exit = protocol.sign_clear("alice", "alice-b", "m4", 103);
    require(protocol.verify_clear(new_label, "m4", after_exit),
            "remaining account could not sign after exit");
    protocol.revoke_user("alice");
    require(!protocol.verify_clear(new_label, "m4", after_exit),
            "user-level revocation did not exit the remaining account");
    rejects<std::invalid_argument>([&] { protocol.join("alice-b"); });
    std::cout << "PASS: clear equations, shared user counter, link, replay, tamper, and exit\n";
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    try {
        run(argv[1]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
