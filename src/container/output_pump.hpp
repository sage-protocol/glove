#pragma once

#include "resource_monitor.hpp"

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace glove::container::detail {

struct output_pump_options {
    // The sink runs on the sole drain worker and must be non-blocking and
    // non-reentrant. Production callers should enqueue into bounded storage.
    using stderr_callback = std::function<void(std::string_view)>;

    int stdout_fd = -1;
    int stderr_fd = -1;
    std::size_t max_frame_bytes = std::size_t{16} * 1024U * 1024U;
    std::size_t max_queued_bytes = std::size_t{4} * 1024U * 1024U;
    // One-shot supervisors may account and discard stdout instead of exposing
    // MCP newline frames. This keeps arbitrary child output draining without
    // allowing an unconsumed frame queue to become an implicit output limit.
    bool discard_stdout = false;
    std::shared_ptr<wall_output_monitor> monitor;
    stderr_callback stderr_sink;
};

// Continuously drains a child's stdout and stderr on one worker. Stdout is
// split into newline-framed messages behind a bounded queue; when that queue
// backpressures stdout, stderr remains in the poll set. The read descriptors
// transfer to this object only when create() succeeds.
class output_pump {
    struct construction_token {};

    enum class error_code : unsigned char {
        none,
        stopped,
        poll_failed,
        stdout_read_failed,
        stderr_read_failed,
        output_limit,
        frame_limit,
        unterminated_frame,
        stderr_callback_failed,
        supervisor_failure,
        stdout_eof,
    };

    struct queued_frame {
        std::string content;
        std::size_t wire_bytes = 0;
    };

public:
    using pointer_result = std::expected<std::unique_ptr<output_pump>, std::string>;

    output_pump(
        [[maybe_unused]] construction_token token,
        output_pump_options options,
        int wake_read_fd,
        int wake_write_fd
    );

    output_pump(const output_pump&) = delete;
    auto operator=(const output_pump&) -> output_pump& = delete;
    output_pump(output_pump&&) = delete;
    auto operator=(output_pump&&) -> output_pump& = delete;
    ~output_pump();

    [[nodiscard]] static auto create(output_pump_options options) -> pointer_result;

    [[nodiscard]] auto recv_frame() -> std::expected<std::string, std::string>;
    // Join after the child closes both output pipes, preserving all bytes that
    // arrived before EOF. Callers must not use this while writers remain live.
    [[nodiscard]] auto finish_draining() -> std::expected<void, std::string>;
    void stop() noexcept;

private:
    void worker_loop() noexcept;
    void drain_loop();
    [[nodiscard]] auto stdout_poll_enabled_locked() -> bool;
    void queue_buffered_frames_locked();
    [[nodiscard]] auto read_stdout_once() -> bool;
    [[nodiscard]] auto read_stderr_once() -> bool;
    [[nodiscard]] auto account_output(std::size_t bytes) -> bool;
    void set_error_locked(error_code error, int system_error = 0) noexcept;
    void signal_worker() const noexcept;
    void close_descriptors() noexcept;
    [[nodiscard]] auto error_message_locked() const -> std::string;

    int stdout_fd_;
    int stderr_fd_;
    int wake_read_fd_;
    int wake_write_fd_;
    std::size_t max_frame_bytes_;
    std::size_t max_queued_bytes_;
    bool discard_stdout_;
    std::shared_ptr<wall_output_monitor> monitor_;
    output_pump_options::stderr_callback stderr_sink_;

    mutable std::mutex state_mutex_;
    std::condition_variable state_changed_;
    std::deque<queued_frame> frames_;
    std::string stdout_buffer_;
    std::size_t queued_bytes_ = 0;
    error_code error_ = error_code::none;
    int system_error_ = 0;
    bool stop_requested_ = false;
    bool stdout_eof_ = false;
    bool stderr_eof_ = false;
    bool worker_done_ = false;

    std::mutex finish_mutex_;
    // See resource_monitor.hpp: the supported Linux libc++ requires explicit
    // thread notification and joining instead of std::jthread.
    std::thread worker_;
};

} // namespace glove::container::detail
