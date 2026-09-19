#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace lktrs::protocol {

// Owns one directly spawned child. Requests share one stream and are serialized
// internally; the object does not multiplex concurrent operations. stderr is
// inherited. Resource limits are an external deployment responsibility.
// stdin/stdout carry a four-byte big-endian length followed by frame bytes.
class NativeProcess final {
public:
    static constexpr std::size_t max_frame_bytes = 16 * 1024 * 1024;

    // executable is a path, not a shell command; args excludes argv[0].
    explicit NativeProcess(std::string executable, std::vector<std::string> args);
    ~NativeProcess();

    NativeProcess(const NativeProcess&) = delete;
    NativeProcess& operator=(const NativeProcess&) = delete;
    NativeProcess(NativeProcess&&) = delete;
    NativeProcess& operator=(NativeProcess&&) = delete;

    // timeout covers the complete request write and response read, including
    // child startup. A timeout or transport/protocol failure kills and reaps
    // the child; further requests then fail. Invalid arguments are rejected
    // before writing, so a too-large request does not poison a live process.
    std::vector<std::uint8_t> request(const std::vector<std::uint8_t>& payload,
                                    std::chrono::milliseconds timeout);

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace lktrs::protocol
