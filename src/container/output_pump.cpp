#include "output_pump.hpp"

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <deque>
#include <limits>
#include <new>
#include <system_error>
#include <utility>

namespace glove::container::detail {

namespace {

constexpr std::size_t read_chunk_bytes = 4096;

class unique_fd {
public:
    explicit unique_fd(int fd = -1) noexcept : fd_{fd} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(fd_, -1); }

    void reset() noexcept {
        if (fd_ >= 0) {
            static_cast<void>(::close(fd_));
            fd_ = -1;
        }
    }

private:
    int fd_;
};

auto add_fd_flags(int fd, int command, int flags) -> bool {
    const int current = ::fcntl(fd, command);
    if (current < 0) {
        return false;
    }
    const int set_command = command == F_GETFD ? F_SETFD : F_SETFL;
    const auto combined = static_cast<unsigned int>(current) | static_cast<unsigned int>(flags);
    return ::fcntl(fd, set_command, static_cast<int>(combined)) == 0;
}

auto make_wake_pipe() -> std::expected<std::array<unique_fd, 2>, std::string> {
    std::array<int, 2> raw = {-1, -1};
    if (::pipe(raw.data()) != 0) {
        return std::unexpected(
            std::string{"create output-pump wake pipe: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }
    std::array<unique_fd, 2> owned = {unique_fd{raw[0]}, unique_fd{raw[1]}};
    if (!add_fd_flags(owned[0].get(), F_GETFD, FD_CLOEXEC) ||
        !add_fd_flags(owned[1].get(), F_GETFD, FD_CLOEXEC) ||
        !add_fd_flags(owned[0].get(), F_GETFL, O_NONBLOCK) ||
        !add_fd_flags(owned[1].get(), F_GETFL, O_NONBLOCK)) {
        return std::unexpected(
            std::string{"configure output-pump wake pipe: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }
    return owned;
}

} // namespace

output_pump::output_pump(
    [[maybe_unused]] construction_token token,
    output_pump_options options,
    int wake_read_fd,
    int wake_write_fd
)
    : stdout_fd_{options.stdout_fd},
      stderr_fd_{options.stderr_fd},
      wake_read_fd_{wake_read_fd},
      wake_write_fd_{wake_write_fd},
      max_frame_bytes_{options.max_frame_bytes},
      max_queued_bytes_{options.max_queued_bytes},
      discard_stdout_{options.discard_stdout},
      monitor_{std::move(options.monitor)},
      stderr_sink_{std::move(options.stderr_sink)},
      worker_{[this] { worker_loop(); }} {}

output_pump::~output_pump() {
    stop();
}

auto output_pump::create(output_pump_options options) -> pointer_result {
    if (options.stdout_fd < 0 || options.stderr_fd < 0 || options.stdout_fd == options.stderr_fd ||
        options.max_frame_bytes == 0 || options.max_queued_bytes == 0) {
        return std::unexpected(std::string{"invalid output-pump configuration"});
    }
    auto wake_pipe = make_wake_pipe();
    if (!wake_pipe) {
        return std::unexpected(wake_pipe.error());
    }
    try {
        auto pump = std::make_unique<output_pump>(
            construction_token{}, std::move(options), (*wake_pipe)[0].get(), (*wake_pipe)[1].get()
        );
        static_cast<void>((*wake_pipe)[0].release());
        static_cast<void>((*wake_pipe)[1].release());
        return pump;
    } catch (const std::system_error& error) {
        return std::unexpected(std::string{"start output-pump worker: "} + error.what());
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate output pump"});
    }
}

auto output_pump::recv_frame() -> std::expected<std::string, std::string> {
    std::unique_lock lock{state_mutex_};
    state_changed_.wait(lock, [this] {
        return !frames_.empty() || error_ != error_code::none || stop_requested_ || worker_done_;
    });
    if (stop_requested_) {
        return std::unexpected(error_message_locked());
    }
    if (!frames_.empty()) {
        queued_frame frame = std::move(frames_.front());
        frames_.pop_front();
        queued_bytes_ -= frame.wire_bytes;
        signal_worker();
        lock.unlock();
        return std::move(frame.content);
    }
    return std::unexpected(error_message_locked());
}

auto output_pump::finish_draining() -> std::expected<void, std::string> {
    const std::lock_guard finish_lock{finish_mutex_};
    if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
    }
    close_descriptors();
    const std::lock_guard state_lock{state_mutex_};
    if (error_ == error_code::none || error_ == error_code::output_limit) {
        return {};
    }
    return std::unexpected(error_message_locked());
}

void output_pump::stop() noexcept {
    const std::lock_guard finish_lock{finish_mutex_};
    {
        const std::lock_guard state_lock{state_mutex_};
        if (!stop_requested_) {
            stop_requested_ = true;
            if (error_ == error_code::none) {
                error_ = error_code::stopped;
            }
            state_changed_.notify_all();
        }
    }
    signal_worker();
    if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
    }
    close_descriptors();
}

void output_pump::worker_loop() noexcept {
    try {
        drain_loop();
    } catch (...) {
        const std::lock_guard lock{state_mutex_};
        set_error_locked(error_code::supervisor_failure);
    }
    const std::lock_guard lock{state_mutex_};
    worker_done_ = true;
    state_changed_.notify_all();
}

void output_pump::drain_loop() {
    for (;;) {
        bool poll_stdout = false;
        bool poll_stderr = false;
        {
            const std::lock_guard lock{state_mutex_};
            if (stop_requested_ || error_ != error_code::none) {
                return;
            }
            poll_stdout = stdout_poll_enabled_locked();
            poll_stderr = !stderr_eof_;
            if (error_ != error_code::none || (!poll_stdout && stdout_eof_ && stderr_eof_)) {
                return;
            }
        }

        std::array<::pollfd, 3> descriptors = {
            ::pollfd{.fd = wake_read_fd_, .events = POLLIN, .revents = 0},
            ::pollfd{
                .fd = poll_stdout ? stdout_fd_ : -1,
                .events = POLLIN,
                .revents = 0,
            },
            ::pollfd{
                .fd = poll_stderr ? stderr_fd_ : -1,
                .events = POLLIN,
                .revents = 0,
            },
        };
        const int ready = ::poll(descriptors.data(), descriptors.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            const std::lock_guard lock{state_mutex_};
            set_error_locked(error_code::poll_failed, errno);
            return;
        }
        if (descriptors[0].revents != 0) {
            std::array<char, 64> discarded{};
            while (::read(wake_read_fd_, discarded.data(), discarded.size()) > 0) {}
        }
        {
            const std::lock_guard lock{state_mutex_};
            if (stop_requested_) {
                return;
            }
        }
        if (descriptors[1].revents != 0 && !read_stdout_once()) {
            return;
        }
        if (descriptors[2].revents != 0 && !read_stderr_once()) {
            return;
        }
    }
}

auto output_pump::stdout_poll_enabled_locked() -> bool {
    if (stdout_eof_) {
        return false;
    }
    if (discard_stdout_) {
        return true;
    }
    queue_buffered_frames_locked();
    if (error_ != error_code::none) {
        return false;
    }
    if (stdout_buffer_.find('\n') != std::string::npos) {
        return false;
    }
    return !stdout_buffer_.empty() || frames_.empty() || queued_bytes_ < max_queued_bytes_;
}

void output_pump::queue_buffered_frames_locked() {
    for (;;) {
        const auto newline = stdout_buffer_.find('\n');
        if (newline == std::string::npos) {
            if (stdout_buffer_.size() > max_frame_bytes_) {
                set_error_locked(error_code::frame_limit);
            }
            return;
        }
        if (newline > max_frame_bytes_) {
            set_error_locked(error_code::frame_limit);
            return;
        }
        const std::size_t wire_bytes = newline + 1;
        if (!frames_.empty() && (queued_bytes_ >= max_queued_bytes_ ||
                                 wire_bytes > max_queued_bytes_ - queued_bytes_)) {
            return;
        }
        queued_frame frame{
            .content = stdout_buffer_.substr(0, newline),
            .wire_bytes = wire_bytes,
        };
        stdout_buffer_.erase(0, wire_bytes);
        if (wire_bytes > std::numeric_limits<std::size_t>::max() - queued_bytes_) {
            set_error_locked(error_code::supervisor_failure);
            return;
        }
        frames_.push_back(std::move(frame));
        queued_bytes_ += wire_bytes;
        state_changed_.notify_all();
    }
}

auto output_pump::read_stdout_once() -> bool {
    std::array<char, read_chunk_bytes> chunk{};
    const ::ssize_t count = ::read(stdout_fd_, chunk.data(), chunk.size());
    if (count < 0) {
        if (errno == EINTR) {
            return true;
        }
        const std::lock_guard lock{state_mutex_};
        set_error_locked(error_code::stdout_read_failed, errno);
        return false;
    }
    if (count == 0) {
        const std::lock_guard lock{state_mutex_};
        stdout_eof_ = true;
        if (discard_stdout_) {
            return true;
        }
        queue_buffered_frames_locked();
        if (error_ == error_code::none && !stdout_buffer_.empty()) {
            set_error_locked(error_code::unterminated_frame);
        } else if (error_ == error_code::none && frames_.empty()) {
            set_error_locked(error_code::stdout_eof);
        }
        return error_ == error_code::none;
    }
    const auto bytes = static_cast<std::size_t>(count);
    if (!account_output(bytes)) {
        const std::lock_guard lock{state_mutex_};
        set_error_locked(error_code::output_limit);
        return false;
    }
    if (discard_stdout_) {
        return true;
    }
    const std::lock_guard lock{state_mutex_};
    stdout_buffer_.append(chunk.data(), bytes);
    queue_buffered_frames_locked();
    return error_ == error_code::none;
}

auto output_pump::read_stderr_once() -> bool {
    std::array<char, read_chunk_bytes> chunk{};
    const ::ssize_t count = ::read(stderr_fd_, chunk.data(), chunk.size());
    if (count < 0) {
        if (errno == EINTR) {
            return true;
        }
        const std::lock_guard lock{state_mutex_};
        set_error_locked(error_code::stderr_read_failed, errno);
        return false;
    }
    if (count == 0) {
        const std::lock_guard lock{state_mutex_};
        stderr_eof_ = true;
        return true;
    }
    const auto bytes = static_cast<std::size_t>(count);
    if (!account_output(bytes)) {
        const std::lock_guard lock{state_mutex_};
        set_error_locked(error_code::output_limit);
        return false;
    }
    if (stderr_sink_) {
        try {
            stderr_sink_(std::string_view{chunk.data(), bytes});
        } catch (...) {
            const std::lock_guard lock{state_mutex_};
            set_error_locked(error_code::stderr_callback_failed);
            return false;
        }
    }
    return true;
}

auto output_pump::account_output(std::size_t bytes) -> bool {
    return !monitor_ || monitor_->account_terminal_output(bytes);
}

void output_pump::set_error_locked(error_code error, int system_error) noexcept {
    if (error_ == error_code::none) {
        error_ = error;
        system_error_ = system_error;
        state_changed_.notify_all();
    }
}

void output_pump::signal_worker() const noexcept {
    if (wake_write_fd_ < 0) {
        return;
    }
    constexpr char wake = '1';
    const ::ssize_t result = ::write(wake_write_fd_, &wake, 1);
    static_cast<void>(result);
}

void output_pump::close_descriptors() noexcept {
    for (int* fd : {&stdout_fd_, &stderr_fd_, &wake_read_fd_, &wake_write_fd_}) {
        if (*fd >= 0) {
            static_cast<void>(::close(*fd));
            *fd = -1;
        }
    }
}

auto output_pump::error_message_locked() const -> std::string {
    const auto system_message = [this](std::string_view prefix) {
        return std::string{prefix} +
               std::error_code{system_error_, std::generic_category()}.message();
    };
    switch (error_) {
    case error_code::none:
    case error_code::stdout_eof:
        return std::string{"unexpected eof from agent"};
    case error_code::stopped:
        return std::string{"output pump stopped"};
    case error_code::poll_failed:
        return system_message("poll agent output: ");
    case error_code::stdout_read_failed:
        return system_message("read agent stdout: ");
    case error_code::stderr_read_failed:
        return system_message("read agent stderr: ");
    case error_code::output_limit:
        return std::string{"terminal output limit exceeded"};
    case error_code::frame_limit:
        return std::string{"frame exceeds max_frame_bytes"};
    case error_code::unterminated_frame:
        return std::string{"unterminated frame at stdout eof"};
    case error_code::stderr_callback_failed:
        return std::string{"agent stderr sink failed"};
    case error_code::supervisor_failure:
        return std::string{"output pump supervisor failure"};
    }
    return std::string{"output pump supervisor failure"};
}

} // namespace glove::container::detail
