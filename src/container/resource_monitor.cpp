#include "resource_monitor.hpp"

#include <exception>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace glove::container::detail {

wall_output_monitor::wall_output_monitor(
    [[maybe_unused]] construction_token token,
    clock::time_point started_at,
    std::uint64_t wall_time_limit_ms,
    std::uint64_t terminal_output_limit_bytes,
    terminate_callback terminate
)
    : started_at_{started_at},
      deadline_{started_at_ + std::chrono::milliseconds{wall_time_limit_ms}},
      terminal_output_limit_bytes_{terminal_output_limit_bytes},
      terminate_{std::move(terminate)},
      watchdog_{[this] { watchdog_loop(); }} {}

wall_output_monitor::~wall_output_monitor() {
    finish();
}

auto wall_output_monitor::create(
    std::uint64_t wall_time_limit_ms,
    std::uint64_t terminal_output_limit_bytes,
    terminate_callback terminate
) -> std::expected<std::shared_ptr<wall_output_monitor>, std::string> {
    if (wall_time_limit_ms == 0 || terminal_output_limit_bytes == 0 || !terminate) {
        return std::unexpected(std::string{"wall/output monitor requires limits and termination"});
    }
    const auto started_at = clock::now();
    const auto available =
        std::chrono::duration_cast<std::chrono::milliseconds>(clock::time_point::max() - started_at)
            .count();
    if (available <= 0 || wall_time_limit_ms > static_cast<std::uint64_t>(available)) {
        return std::unexpected(std::string{"wall-time limit exceeds monotonic clock range"});
    }
    try {
        return std::make_shared<wall_output_monitor>(
            construction_token{},
            started_at,
            wall_time_limit_ms,
            terminal_output_limit_bytes,
            std::move(terminate)
        );
    } catch (const std::system_error& error) {
        return std::unexpected(std::string{"start wall-time watchdog: "} + error.what());
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate wall/output monitor"});
    }
}

auto wall_output_monitor::account_terminal_output(std::size_t bytes) noexcept -> bool {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    const auto count = static_cast<std::uint64_t>(bytes);
    const std::lock_guard lock{state_mutex_};
    if (finished_) {
        return false;
    }
    if (count > std::numeric_limits<std::uint64_t>::max() - terminal_output_bytes_) {
        terminal_output_bytes_ = std::numeric_limits<std::uint64_t>::max();
    } else {
        terminal_output_bytes_ += count;
    }
    if (!forced_cause_ && terminal_output_bytes_ > terminal_output_limit_bytes_) {
        request_termination_locked(resource_termination_cause::terminal_output_limit);
    }
    return !forced_cause_.has_value();
}

auto wall_output_monitor::request_termination(resource_termination_cause cause) noexcept -> bool {
    if (cause == resource_termination_cause::exited ||
        cause == resource_termination_cause::signaled) {
        return false;
    }
    const std::lock_guard lock{state_mutex_};
    if (finished_ || forced_cause_) {
        return false;
    }
    request_termination_locked(cause);
    return true;
}

void wall_output_monitor::finish() noexcept {
    const std::lock_guard finish_lock{finish_mutex_};
    {
        const std::lock_guard state_lock{state_mutex_};
        if (!finished_) {
            finished_ = true;
            finished_at_ = clock::now();
            state_changed_.notify_all();
        }
    }
    if (watchdog_.joinable() && watchdog_.get_id() != std::this_thread::get_id()) {
        watchdog_.join();
    }
}

auto wall_output_monitor::snapshot() const noexcept -> wall_output_snapshot {
    const std::lock_guard lock{state_mutex_};
    const auto observed_at = finished_ ? finished_at_ : clock::now();
    return {
        .wall_time_ms = elapsed_ms_locked(observed_at),
        .terminal_output_bytes = terminal_output_bytes_,
        .forced_cause = forced_cause_,
        .termination_callback_failed = termination_callback_failed_,
    };
}

void wall_output_monitor::watchdog_loop() noexcept {
    std::unique_lock lock{state_mutex_};
    const bool stopped = state_changed_.wait_until(lock, deadline_, [this] {
        return finished_ || forced_cause_.has_value();
    });
    if (!stopped) {
        request_termination_locked(resource_termination_cause::wall_time_limit);
    }
}

void wall_output_monitor::request_termination_locked(resource_termination_cause cause) noexcept {
    if (finished_ || forced_cause_) {
        return;
    }
    forced_cause_ = cause;
    try {
        terminate_(cause);
    } catch (...) {
        forced_cause_ = resource_termination_cause::supervisor_error;
        termination_callback_failed_ = true;
    }
    state_changed_.notify_all();
}

auto wall_output_monitor::elapsed_ms_locked(clock::time_point now) const noexcept -> std::uint64_t {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - started_at_);
    return elapsed.count() > 0 ? static_cast<std::uint64_t>(elapsed.count()) : 0;
}

} // namespace glove::container::detail
