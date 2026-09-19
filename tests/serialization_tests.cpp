#include "lktrs/crypto/ddh.hpp"
#include "lktrs/crypto/pairing.hpp"
#include "lktrs/protocol/clear.hpp"
#include "lktrs/protocol/serialization.hpp"

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
    return crypto::PairingContext::from_trusted_parameters("serialization-test", parameters);
}

void run(const std::string& path) {
    auto parameters = protocol::Parameters::for_testing(
        pairing_from_file(path), crypto::DdhContext::ristretto255("serialization-gp"),
        "issue-serialization", 3, 4);
    protocol::ClearProtocol system(std::move(parameters));
    system.create_user("alice");
    const auto account = system.create_account("alice", "alice-a");
    system.join(account.public_key.account_id);
    const auto label = system.current_label();
    const auto signature = system.sign_clear("alice", "alice-a", "payload", 77);

    const auto label_bytes = protocol::encode_ring_label(label);
    require(label_bytes == protocol::encode_ring_label(label), "ring encoding is not deterministic");
    const auto decoded = protocol::decode_ring_label(system.parameters().pairing(),
                                                     system.parameters().ddh(), label_bytes);
    require(decoded.issue == label.issue && decoded.accounts.size() == label.accounts.size(),
            "ring encoding did not decode its header");
    require(decoded.accounts.front().account_id == label.accounts.front().account_id &&
                decoded.accounts.front().u_i.equals(label.accounts.front().u_i) &&
                decoded.accounts.front().y_i.equals(label.accounts.front().y_i) &&
                decoded.accounts.front().member.equals(label.accounts.front().member),
            "ring encoding did not round-trip the account key");
    auto trailing = label_bytes;
    trailing.push_back(0);
    rejects<std::invalid_argument>([&] {
        (void)protocol::decode_ring_label(system.parameters().pairing(),
                                          system.parameters().ddh(), trailing);
    });
    auto oversized = label_bytes;
    oversized.resize(16 * 1024 * 1024 + 1);
    rejects<std::length_error>([&] {
        (void)protocol::decode_ring_label(system.parameters().pairing(),
                                          system.parameters().ddh(), oversized);
    });
    const auto transcript = protocol::encode_challenge_transcript(label, "payload", signature.nym, 77);
    require(transcript == protocol::encode_challenge_transcript(label, "payload", signature.nym, 77),
            "challenge encoding is not deterministic");
    const auto expected_challenge = crypto::Scalar::hash_to_scalar(
        system.parameters().pairing(), "lktrs/challenge/v1", transcript);
    require(expected_challenge.equals(signature.challenge),
            "ClearProtocol challenge is not derived from canonical transcript");
    require(transcript != protocol::encode_challenge_transcript(label, "payload-mutated", signature.nym, 77),
            "message mutation did not change challenge transcript");
    require(transcript != protocol::encode_challenge_transcript(label, "payload", signature.nym, 78),
            "timestamp mutation did not change challenge transcript");

    auto changed_label = label;
    changed_label.issue = "other-issue";
    require(transcript != protocol::encode_challenge_transcript(changed_label, "payload", signature.nym, 77),
            "issue mutation did not change challenge transcript");
    const auto public_bytes = protocol::encode_public_signature(signature);
    const auto decoded_signature = protocol::decode_public_signature(
        system.parameters().pairing(), system.parameters().ddh(), public_bytes);
    require(decoded_signature.nym.equals(signature.nym) &&
                decoded_signature.accumulator_value.equals(signature.accumulator_value) &&
                decoded_signature.one_time_pass.equals(signature.one_time_pass) &&
                decoded_signature.trace_tag.equals(signature.trace_tag) &&
                decoded_signature.challenge.equals(signature.challenge) &&
                decoded_signature.timestamp == signature.timestamp,
            "public signature did not round-trip");
    auto changed_signature = signature;
    changed_signature.timestamp++;
    require(public_bytes != protocol::encode_public_signature(changed_signature),
            "signature mutation did not change public encoding");
    auto signature_trailing = public_bytes;
    signature_trailing.push_back(0);
    rejects<std::invalid_argument>([&] {
        (void)protocol::decode_public_signature(system.parameters().pairing(),
                                                system.parameters().ddh(), signature_trailing);
    });
    std::cout << "PASS: canonical ring, transcript and public signature encodings\n";
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
