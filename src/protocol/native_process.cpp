#include "lktrs/protocol/native_process.hpp"

#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <mutex>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

extern char** environ;

namespace lktrs::protocol {
namespace {

using Clock = std::chrono::steady_clock;

[[noreturn]] void system_failure(const char* operation, int code = errno) {
    throw std::system_error(code, std::generic_category(), operation);
}

void spawn_check(int result, const char* operation) {
    if (result != 0) system_failure(operation, result);
}

class Descriptor final {
public:
    explicit Descriptor(int fd = -1) noexcept : fd_(fd) {}
    ~Descriptor() { reset(); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;

    int get() const noexcept { return fd_; }
    int release() noexcept {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }
    void reset(int fd = -1) noexcept {
        // Do not retry close on EINTR: another thread could reuse the number.
        if (fd_ >= 0) (void)::close(fd_);
        fd_ = fd;
    }

private:
    int fd_;
};

void make_pipe(Descriptor& read_end, Descriptor& write_end) {
    int raw[2];
    if (::pipe(raw) != 0) system_failure("native process pipe");
    read_end.reset(raw[0]);
    write_end.reset(raw[1]);
    for (auto* descriptor : {&read_end, &write_end}) {
        // Keep all original pipe descriptors away from stdin/out/err even if
        // the caller has closed a standard descriptor. dup2 actions below can
        // then close every original without accidentally closing child stdio.
        if (descriptor->get() <= STDERR_FILENO) {
            const int replacement = ::fcntl(descriptor->get(), F_DUPFD_CLOEXEC, 3);
            if (replacement < 0) system_failure("native process duplicate pipe");
            descriptor->reset(replacement);
        } else if (::fcntl(descriptor->get(), F_SETFD, FD_CLOEXEC) < 0) {
            system_failure("native process close-on-exec");
        }
    }
}

void nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        system_failure("native process nonblocking pipe");
    }
}

class SpawnActions final {
public:
    SpawnActions() { spawn_check(posix_spawn_file_actions_init(&value_), "spawn actions init"); }
    ~SpawnActions() { (void)posix_spawn_file_actions_destroy(&value_); }
    SpawnActions(const SpawnActions&) = delete;
    SpawnActions& operator=(const SpawnActions&) = delete;

    void duplicate(int source, int target) {
        spawn_check(posix_spawn_file_actions_adddup2(&value_, source, target), "spawn duplicate");
    }
    void close(int fd) {
        spawn_check(posix_spawn_file_actions_addclose(&value_, fd), "spawn close");
    }
    const posix_spawn_file_actions_t* get() const { return &value_; }

private:
    posix_spawn_file_actions_t value_{};
};

// A closed child stdin must raise an exception, not terminate the host via
// SIGPIPE. Block only this thread while writing, consume only a newly generated
// pending SIGPIPE, then restore the caller's mask. No global signal handler or
// disposition is changed. sigwait is available on both macOS and Linux.
class PipeSignalBlock final {
public:
    PipeSignalBlock() {
        sigemptyset(&pipe_signal_);
        sigaddset(&pipe_signal_, SIGPIPE);
        const int error = pthread_sigmask(SIG_BLOCK, &pipe_signal_, &previous_mask_);
        if (error != 0) system_failure("native process block SIGPIPE", error);
        sigset_t pending;
        if (sigpending(&pending) != 0) {
            const int pending_error = errno;
            (void)pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
            system_failure("native process pending signals", pending_error);
        }
        already_pending_ = sigismember(&pending, SIGPIPE) == 1;
    }
    ~PipeSignalBlock() {
        if (broken_pipe_ && !already_pending_) {
            sigset_t pending;
            if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
                int signal = 0;
                (void)sigwait(&pipe_signal_, &signal);
            }
        }
        (void)pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
    }
    PipeSignalBlock(const PipeSignalBlock&) = delete;
    PipeSignalBlock& operator=(const PipeSignalBlock&) = delete;
    void broken_pipe() noexcept { broken_pipe_ = true; }

private:
    sigset_t pipe_signal_{};
    sigset_t previous_mask_{};
    bool already_pending_ = false;
    bool broken_pipe_ = false;
};

void await_ready(int fd, short events, Clock::time_point deadline) {
    for (;;) {
        const auto remaining = deadline - Clock::now();
        if (remaining <= Clock::duration::zero()) {
            throw std::runtime_error("native process request timed out");
        }
        const auto millis = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        const int wait = millis > INT_MAX ? INT_MAX : static_cast<int>(millis);
        pollfd descriptor{fd, events, 0};
        const int result = ::poll(&descriptor, 1, wait);
        if (result < 0) {
            if (errno == EINTR) continue;
            system_failure("native process poll");
        }
        if (result == 0) continue; // Recheck the common deadline, including long polls.
        if (Clock::now() >= deadline) {
            throw std::runtime_error("native process request timed out");
        }
        if ((descriptor.revents & POLLNVAL) != 0) {
            throw std::runtime_error("native process pipe is invalid");
        }
        if ((descriptor.revents & (events | POLLHUP | POLLERR)) != 0) return;
    }
}

void write_all(int fd, const std::uint8_t* bytes, std::size_t size, Clock::time_point deadline) {
    PipeSignalBlock signals;
    std::size_t offset = 0;
    while (offset < size) {
        await_ready(fd, POLLOUT, deadline);
        const ssize_t written = ::write(fd, bytes + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            const int write_error = errno;
            if (write_error == EPIPE) signals.broken_pipe();
            system_failure("native process write", write_error);
        }
        if (written == 0) throw std::runtime_error("native process write made no progress");
        offset += static_cast<std::size_t>(written);
    }
}

void read_all(int fd, std::uint8_t* bytes, std::size_t size, Clock::time_point deadline) {
    std::size_t offset = 0;
    while (offset < size) {
        await_ready(fd, POLLIN, deadline);
        const ssize_t received = ::read(fd, bytes + offset, size - offset);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            system_failure("native process read");
        }
        if (received == 0) throw std::runtime_error("native process EOF before complete response");
        offset += static_cast<std::size_t>(received);
    }
}

} // namespace

struct NativeProcess::State {
    ~State() { stop(); }

    void stop() noexcept {
        input.reset();
        output.reset();
        if (pid <= 0) return;
        int status = 0;
        pid_t result;
        do {
            result = ::waitpid(pid, &status, WNOHANG);
        } while (result < 0 && errno == EINTR);
        // Reap an already-exited child without signalling it. In particular,
        // ECHILD means this process no longer owns that PID (for example if
        // the host auto-reaped SIGCHLD), so do not send a signal in that case.
        if (result == 0) {
            (void)::kill(pid, SIGKILL);
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        }
        pid = -1;
    }

    Descriptor input;
    Descriptor output;
    pid_t pid = -1;
    std::mutex request_mutex;
};

NativeProcess::NativeProcess(std::string executable, std::vector<std::string> args)
    : state_(std::make_unique<State>()) {
    if (executable.empty() || executable.find('\0') != std::string::npos) {
        throw std::invalid_argument("native process executable must be a nonempty path");
    }
    for (const auto& argument : args) {
        if (argument.find('\0') != std::string::npos) {
            throw std::invalid_argument("native process argument contains a NUL byte");
        }
    }
    Descriptor child_input, parent_input, parent_output, child_output;
    make_pipe(child_input, parent_input);
    make_pipe(parent_output, child_output);
    nonblocking(parent_input.get());
    nonblocking(parent_output.get());

    SpawnActions actions;
    actions.duplicate(child_input.get(), STDIN_FILENO);
    actions.duplicate(child_output.get(), STDOUT_FILENO);
    for (const int fd : {child_input.get(), parent_input.get(), parent_output.get(), child_output.get()}) {
        actions.close(fd);
    }
    std::vector<char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(executable.data());
    for (auto& argument : args) argv.push_back(argument.data());
    argv.push_back(nullptr);
    pid_t child_pid = -1;
    spawn_check(::posix_spawn(&child_pid, executable.c_str(), actions.get(), nullptr,
                              argv.data(), environ), "native process spawn");
    state_->pid = child_pid;
    state_->input.reset(parent_input.release());
    state_->output.reset(parent_output.release());
}

NativeProcess::~NativeProcess() = default;

std::vector<std::uint8_t> NativeProcess::request(const std::vector<std::uint8_t>& payload,
                                               std::chrono::milliseconds timeout) {
    // A single child stream carries one request and one response at a time.
    // Serialize callers here so concurrent users cannot interleave frames or
    // consume each other's response. The process remains single-stream.
    std::lock_guard<std::mutex> lock(state_->request_mutex);
    if (payload.size() > max_frame_bytes) {
        throw std::length_error("native process request exceeds 16 MiB frame limit");
    }
    const auto now = Clock::now();
    if (timeout <= std::chrono::milliseconds::zero() ||
        timeout > std::chrono::duration_cast<std::chrono::milliseconds>(Clock::time_point::max() - now)) {
        throw std::invalid_argument("native process timeout must be positive and representable");
    }
    if (state_->pid <= 0) throw std::runtime_error("native process is no longer running");
    const auto deadline = now + timeout;
    try {
        const auto length = static_cast<std::uint32_t>(payload.size());
        std::array<std::uint8_t, 4> header{
            static_cast<std::uint8_t>(length >> 24), static_cast<std::uint8_t>(length >> 16),
            static_cast<std::uint8_t>(length >> 8), static_cast<std::uint8_t>(length)};
        write_all(state_->input.get(), header.data(), header.size(), deadline);
        write_all(state_->input.get(), payload.data(), payload.size(), deadline);
        read_all(state_->output.get(), header.data(), header.size(), deadline);
        const std::uint32_t response_length = (static_cast<std::uint32_t>(header[0]) << 24) |
            (static_cast<std::uint32_t>(header[1]) << 16) |
            (static_cast<std::uint32_t>(header[2]) << 8) | static_cast<std::uint32_t>(header[3]);
        if (response_length > max_frame_bytes) {
            throw std::length_error("native process response exceeds 16 MiB frame limit");
        }
        std::vector<std::uint8_t> response(response_length);
        read_all(state_->output.get(), response.data(), response.size(), deadline);
        return response;
    } catch (...) {
        state_->stop();
        throw;
    }
}

} // namespace lktrs::protocol
