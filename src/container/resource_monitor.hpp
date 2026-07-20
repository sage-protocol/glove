#pragma once

#include "glove/container/profile.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace glove::container::detail {

struct wall_output_snapshot {
    std::uint64_t wall_time_ms = 0;
    std::uint64_t terminal_output_bytes = 0;
    std::optional<resource_termination_cause> forced_cause;
    bool termination_callback_failed = false;
};

// Shared enforcement state for a process handle and its stdout/stderr
// drainers. The termination callback must be non-blocking and must not call
// back into this monitor; signaling a process or cgroup is the intended use.
class wall_output_monitor {
    struct construction_token {};

    using clock = std::chrono::steady_clock;

public:
    using terminate_callback = std::function<void(resource_termination_cause)>;

    wall_output_monitor(
        [[maybe_unused]] construction_token token,
        clock::time_point started_at,
        std::uint64_t wall_time_limit_ms,
        std::uint64_t terminal_output_limit_bytes,
        terminate_callback terminate
    );

    wall_output_monitor(const wall_output_monitor&) = delete;
    auto operator=(const wall_output_monitor&) -> wall_output_monitor& = delete;
    wall_output_monitor(wall_output_monitor&&) = delete;
    auto operator=(wall_output_monitor&&) -> wall_output_monitor& = delete;
    ~wall_output_monitor();

    [[nodiscard]] static auto create(
        std::uint64_t wall_time_limit_ms,
        std::uint64_t terminal_output_limit_bytes,
        terminate_callback terminate
    ) -> std::expected<std::shared_ptr<wall_output_monitor>, std::string>;

    // Returns false once this call crosses the output limit or another
    // terminal condition has already won. Bytes at exactly the limit remain
    // legal.
    [[nodiscard]] auto account_terminal_output(std::size_t bytes) noexcept -> bool;

    // Submit a kernel/supervisor limit event into the same first-cause
    // arbitration used by the wall and output paths. Natural exit/signal
    // states are terminal observations, not forced termination requests.
    [[nodiscard]] auto request_termination(resource_termination_cause cause) noexcept -> bool;

    // Stops the deadline without changing a previously selected forced cause.
    // Safe to call repeatedly and from multiple owner threads.
    void finish() noexcept;

    [[nodiscard]] auto snapshot() const noexcept -> wall_output_snapshot;

private:
    void watchdog_loop() noexcept;
    void request_termination_locked(resource_termination_cause cause) noexcept;
    [[nodiscard]] auto elapsed_ms_locked(clock::time_point now) const noexcept -> std::uint64_t;

    clock::time_point started_at_;
    clock::time_point deadline_;
    std::uint64_t terminal_output_limit_bytes_;
    terminate_callback terminate_;

    mutable std::mutex state_mutex_;
    std::condition_variable state_changed_;
    bool finished_ = false;
    clock::time_point finished_at_;
    std::uint64_t terminal_output_bytes_ = 0;
    std::optional<resource_termination_cause> forced_cause_;
    bool termination_callback_failed_ = false;

    std::mutex finish_mutex_;
    // The imported Linux libc++ 18 image does not expose std::jthread, so this
    // owner performs the equivalent notify-and-join protocol explicitly.
    std::thread watchdog_;
};

} // namespace glove::container::detail
