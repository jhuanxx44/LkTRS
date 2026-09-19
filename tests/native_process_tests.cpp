#include "lktrs/protocol/native_process.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <limits>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/wait.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <vector>

using lktrs::protocol::NativeProcess;
using namespace std::chrono_literals;

static_assert(!std::is_copy_constructible_v<NativeProcess>);
static_assert(!std::is_copy_assignable_v<NativeProcess>);

namespace {

using Bytes = std::vector<std::uint8_t>;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Error, class F>
std::string rejects(F&& operation) {
    try {
        operation();
    } catch (const Error& error) {
        return error.what();
    }
    throw std::runtime_error("expected operation to reject");
}

void child_write(const std::uint8_t* bytes, std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t written = ::write(STDOUT_FILENO, bytes + offset, size - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw std::runtime_error("child write failed");
        offset += static_cast<std::size_t>(written);
    }
}

bool child_read(std::uint8_t* bytes, std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t received = ::read(STDIN_FILENO, bytes + offset, size - offset);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) throw std::runtime_error("child read failed");
        if (received == 0 && offset == 0) return false;
        if (received == 0) throw std::runtime_error("child received a truncated request");
        offset += static_cast<std::size_t>(received);
    }
    return true;
}

std::array<std::uint8_t, 4> length_bytes(std::uint32_t length) {
    return {static_cast<std::uint8_t>(length >> 24), static_cast<std::uint8_t>(length >> 16),
            static_cast<std::uint8_t>(length >> 8), static_cast<std::uint8_t>(length)};
}

void child_response(const Bytes& bytes) {
    const auto header = length_bytes(static_cast<std::uint32_t>(bytes.size()));
    child_write(header.data(), header.size());
    child_write(bytes.data(), bytes.size());
}

int echo_child(int argc, char** argv) {
    const std::string mode = argc > 2 ? argv[2] : "";
    for (;;) {
        std::array<std::uint8_t, 4> header{};
        if (!child_read(header.data(), header.size())) return 0;
        const std::uint32_t length = (static_cast<std::uint32_t>(header[0]) << 24) |
            (static_cast<std::uint32_t>(header[1]) << 16) |
            (static_cast<std::uint32_t>(header[2]) << 8) | static_cast<std::uint32_t>(header[3]);
        if (length > NativeProcess::max_frame_bytes) return 2;
        Bytes payload(length);
        if (length != 0 && !child_read(payload.data(), payload.size())) return 3;

        if (mode == "--truncated-header") {
            const std::array<std::uint8_t, 2> prefix{0, 0};
            child_write(prefix.data(), prefix.size());
            return 0;
        }
        if (mode == "--truncated-payload") {
            const auto response_header = length_bytes(4);
            child_write(response_header.data(), response_header.size());
            const std::array<std::uint8_t, 2> partial{1, 2};
            child_write(partial.data(), partial.size());
            return 0;
        }
        if (mode == "--oversize-response") {
            const auto response_header = length_bytes(NativeProcess::max_frame_bytes + 1);
            child_write(response_header.data(), response_header.size());
            return 0;
        }
        if (mode == "--terminal-child") {
            (void)::kill(::getpid(), SIGKILL);
            return 4;
        }
        if (mode == "--argument-echo") {
            if (argc != 4) return 5;
            const std::string argument = argv[3];
            child_response(Bytes(argument.begin(), argument.end()));
            continue;
        }
        if (mode == "--pid-and-stall" || mode == "--closed-input") {
            if (mode == "--closed-input") (void)::close(STDIN_FILENO);
            const auto pid = std::to_string(::getpid());
            child_response(Bytes(pid.begin(), pid.end()));
            for (;;) (void)::pause();
        }
        if (mode == "--slow-echo") std::this_thread::sleep_for(100ms);
        child_response(payload);
    }
}

pid_t read_pid(NativeProcess& process) {
    const auto bytes = process.request({}, 2min);
    const auto value = std::stol(std::string(bytes.begin(), bytes.end()));
    require(value > 0 && value <= std::numeric_limits<pid_t>::max(), "invalid child pid response");
    return static_cast<pid_t>(value);
}

void require_reaped(pid_t pid) {
    int status = 0;
    errno = 0;
    const pid_t result = ::waitpid(pid, &status, WNOHANG);
    require(result == -1 && errno == ECHILD, "owned child was not reaped");
}

class TestDirectory final {
public:
    TestDirectory() {
        const auto root = std::filesystem::current_path() / "local" / "native-process-tests";
        std::filesystem::create_directories(root);
        auto pattern = (root / "case-XXXXXX").string();
        if (::mkdtemp(pattern.data()) == nullptr) {
            throw std::system_error(errno, std::generic_category(), "test directory");
        }
        path = pattern;
    }
    ~TestDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

volatile std::sig_atomic_t signal_count = 0;
void interrupt_handler(int) { ++signal_count; }

class InterruptHandler final {
public:
    InterruptHandler() {
        struct sigaction handler{};
        handler.sa_handler = interrupt_handler;
        sigemptyset(&handler.sa_mask);
        if (::sigaction(SIGUSR1, &handler, &previous_) != 0) {
            throw std::system_error(errno, std::generic_category(), "test signal handler");
        }
    }
    ~InterruptHandler() { (void)::sigaction(SIGUSR1, &previous_, nullptr); }
private:
    struct sigaction previous_{};
};

void run(const std::string& executable) {
    const Bytes binary{0, 255, 128, 1, '\n', '\0', 42};
    {
        NativeProcess process(executable, {"--echo-child"});
        require(process.request(binary, 2min) == binary, "binary frame did not echo exactly");
        require(process.request({}, 2min).empty(), "empty response was not an empty frame");
        Bytes maximum(NativeProcess::max_frame_bytes);
        for (std::size_t i = 0; i < maximum.size(); ++i) maximum[i] = static_cast<std::uint8_t>(i);
        require(process.request(maximum, 2min) == maximum, "maximum-size frame did not round trip");
        maximum.push_back(0);
        rejects<std::length_error>([&] { (void)process.request(maximum, 2min); });
        rejects<std::invalid_argument>([&] { (void)process.request(binary, 0ms); });
        rejects<std::invalid_argument>([&] { (void)process.request(binary, -1ms); });
        require(process.request(binary, 2min) == binary,
                "rejected request arguments poisoned the stream");
    }

    for (const char* mode : {"--truncated-header", "--truncated-payload", "--terminal-child"}) {
        NativeProcess process(executable, {"--echo-child", mode});
        const auto error = rejects<std::runtime_error>([&] { (void)process.request(binary, 2min); });
        require(error.find("EOF") != std::string::npos, "terminal or truncated response did not report EOF");
        rejects<std::runtime_error>([&] { (void)process.request(binary, 2min); });
    }
    {
        NativeProcess process(executable, {"--echo-child", "--oversize-response"});
        rejects<std::length_error>([&] { (void)process.request(binary, 2min); });
        rejects<std::runtime_error>([&] { (void)process.request(binary, 2min); });
    }
    {
        NativeProcess process(executable, {"--echo-child", "--pid-and-stall"});
        const auto pid = read_pid(process);
        const auto start = std::chrono::steady_clock::now();
        const auto error = rejects<std::runtime_error>([&] { (void)process.request(binary, 80ms); });
        require(error.find("timed out") != std::string::npos, "stalled child did not time out");
        require(std::chrono::steady_clock::now() - start < 2s, "read timeout cleanup stalled");
        require_reaped(pid);
        rejects<std::runtime_error>([&] { (void)process.request(binary, 2min); });
    }
    {
        NativeProcess process(executable, {"--echo-child", "--pid-and-stall"});
        const auto pid = read_pid(process);
        const Bytes maximum(NativeProcess::max_frame_bytes, 123);
        const auto start = std::chrono::steady_clock::now();
        const auto error = rejects<std::runtime_error>([&] { (void)process.request(maximum, 80ms); });
        require(error.find("timed out") != std::string::npos, "full request pipe did not time out");
        require(std::chrono::steady_clock::now() - start < 2s, "write timeout cleanup stalled");
        require_reaped(pid);
    }
    {
        NativeProcess process(executable, {"--echo-child", "--closed-input"});
        const auto pid = read_pid(process);
        bool saw_epipe = false;
        try {
            (void)process.request(binary, 2min);
        } catch (const std::system_error& error) {
            saw_epipe = error.code().value() == EPIPE;
        }
        require(saw_epipe, "closed child stdin did not throw EPIPE");
        require_reaped(pid);
    }
    pid_t destroyed_pid = -1;
    {
        NativeProcess process(executable, {"--echo-child", "--pid-and-stall"});
        destroyed_pid = read_pid(process);
    }
    require_reaped(destroyed_pid);

    TestDirectory directory;
    const auto unusual_path = directory.path / "echo child ; $() ' \" with spaces";
    std::filesystem::create_symlink(executable, unusual_path);
    const std::string argument = "spaces; 'single quotes' \"double quotes\" $HOME $(not-a-command) *";
    {
        NativeProcess process(unusual_path.string(), {"--echo-child", "--argument-echo", argument});
        const auto response = process.request(binary, 2min);
        require(std::string(response.begin(), response.end()) == argument,
                "path or argument was interpreted by a shell");
    }
    rejects<std::system_error>([&] {
        NativeProcess missing((directory.path / "missing executable").string(), {});
    });
    rejects<std::invalid_argument>([] { NativeProcess empty("", {}); });
    rejects<std::invalid_argument>([&] {
        NativeProcess embedded_nul(executable, {std::string("bad\0argument", 12)});
    });

    {
        InterruptHandler signals;
        NativeProcess process(executable, {"--echo-child", "--slow-echo"});
        const pthread_t target = pthread_self();
        std::thread interrupter([target] {
            for (int i = 0; i < 5; ++i) {
                std::this_thread::sleep_for(10ms);
                (void)pthread_kill(target, SIGUSR1);
            }
        });
        Bytes response;
        try {
            response = process.request(binary, 2min);
        } catch (...) {
            interrupter.join();
            throw;
        }
        interrupter.join();
        require(response == binary, "EINTR interrupted framed exchange");
        require(signal_count > 0, "signal interruption fixture did not run");
    }
    {
        NativeProcess process(executable, {"--echo-child", "--slow-echo"});
        const Bytes first{'f', 'i', 'r', 's', 't'};
        const Bytes second{'s', 'e', 'c', 'o', 'n', 'd'};
        Bytes first_response;
        Bytes second_response;
        std::exception_ptr first_error;
        std::exception_ptr second_error;
        std::thread first_thread([&] {
            try { first_response = process.request(first, 2min); }
            catch (...) { first_error = std::current_exception(); }
        });
        std::thread second_thread([&] {
            try { second_response = process.request(second, 2min); }
            catch (...) { second_error = std::current_exception(); }
        });
        first_thread.join();
        second_thread.join();
        if (first_error) std::rethrow_exception(first_error);
        if (second_error) std::rethrow_exception(second_error);
        require(first_response == first && second_response == second,
                "concurrent requests interleaved on the native stream");
    }
    std::cout << "PASS: framing, binary/empty/16MiB payloads, size limits, EOF, timeouts, "
                 "SIGPIPE, child cleanup, literal argv, EINTR, and serialized concurrency\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc >= 2 && std::string(argv[1]) == "--echo-child") return echo_child(argc, argv);
        run(std::filesystem::canonical(argv[0]).string());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
