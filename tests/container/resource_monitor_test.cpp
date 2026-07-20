#include "resource_monitor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::resource_termination_cause;
using glove::container::detail::wall_output_monitor;

struct termination_failure {};

auto wall_deadline_test() -> int {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned int calls = 0;
    resource_termination_cause observed = resource_termination_cause::supervisor_error;
    auto monitor = wall_output_monitor::create(20, 1024, [&](resource_termination_cause cause) {
        std::lock_guard lock{mutex};
        observed = cause;
        ++calls;
        changed.notify_all();
    });
    REQUIRE(monitor.has_value());
    {
        std::unique_lock lock{mutex};
        REQUIRE(changed.wait_for(lock, std::chrono::seconds{2}, [&] { return calls == 1; }));
    }
    (*monitor)->finish();
    const auto snapshot = (*monitor)->snapshot();
    REQUIRE(observed == resource_termination_cause::wall_time_limit);
    REQUIRE(snapshot.forced_cause == resource_termination_cause::wall_time_limit);
    REQUIRE(snapshot.wall_time_ms >= 20);
    REQUIRE(!snapshot.termination_callback_failed);
    return 0;
}

auto finish_cancels_deadline_test() -> int {
    std::atomic_uint calls{0};
    auto monitor = wall_output_monitor::create(500, 1024, [&](resource_termination_cause) {
        calls.fetch_add(1);
    });
    REQUIRE(monitor.has_value());
    (*monitor)->finish();
    (*monitor)->finish();
    REQUIRE(calls.load() == 0);
    REQUIRE(!(*monitor)->snapshot().forced_cause.has_value());
    return 0;
}

auto output_budget_test() -> int {
    std::atomic_uint calls{0};
    std::atomic<resource_termination_cause> observed{resource_termination_cause::supervisor_error};
    auto monitor = wall_output_monitor::create(2'000, 10, [&](resource_termination_cause cause) {
        observed.store(cause);
        calls.fetch_add(1);
    });
    REQUIRE(monitor.has_value());
    REQUIRE((*monitor)->account_terminal_output(4));
    REQUIRE((*monitor)->account_terminal_output(6));
    REQUIRE(!(*monitor)->account_terminal_output(1));
    REQUIRE(!(*monitor)->account_terminal_output(1));
    (*monitor)->finish();
    const auto snapshot = (*monitor)->snapshot();
    REQUIRE(snapshot.terminal_output_bytes == 12);
    REQUIRE(snapshot.forced_cause == resource_termination_cause::terminal_output_limit);
    REQUIRE(observed.load() == resource_termination_cause::terminal_output_limit);
    REQUIRE(calls.load() == 1);
    return 0;
}

auto concurrent_output_test() -> int {
    std::atomic_uint calls{0};
    auto monitor = wall_output_monitor::create(2'000, 10, [&](resource_termination_cause) {
        calls.fetch_add(1);
    });
    REQUIRE(monitor.has_value());
    std::thread first{[&] { static_cast<void>((*monitor)->account_terminal_output(8)); }};
    std::thread second{[&] { static_cast<void>((*monitor)->account_terminal_output(8)); }};
    first.join();
    second.join();
    (*monitor)->finish();
    REQUIRE((*monitor)->snapshot().terminal_output_bytes == 16);
    REQUIRE(calls.load() == 1);
    return 0;
}

auto external_cause_arbitration_test() -> int {
    std::atomic_uint calls{0};
    std::atomic<resource_termination_cause> observed{resource_termination_cause::supervisor_error};
    auto monitor = wall_output_monitor::create(2'000, 1024, [&](resource_termination_cause cause) {
        observed.store(cause);
        calls.fetch_add(1);
    });
    REQUIRE(monitor.has_value());
    REQUIRE(!(*monitor)->request_termination(resource_termination_cause::exited));
    REQUIRE((*monitor)->request_termination(resource_termination_cause::cpu_time_limit));
    REQUIRE(!(*monitor)->request_termination(resource_termination_cause::memory_limit));
    REQUIRE(!(*monitor)->account_terminal_output(1));
    (*monitor)->finish();
    const auto snapshot = (*monitor)->snapshot();
    REQUIRE(snapshot.forced_cause == resource_termination_cause::cpu_time_limit);
    REQUIRE(observed.load() == resource_termination_cause::cpu_time_limit);
    REQUIRE(calls.load() == 1);
    return 0;
}

auto saturation_and_callback_failure_test() -> int {
    wall_output_monitor::terminate_callback failure = [](resource_termination_cause) {
        throw termination_failure{};
    };
    auto monitor = wall_output_monitor::create(
        2'000, std::numeric_limits<std::uint64_t>::max() - 1, std::move(failure)
    );
    REQUIRE(monitor.has_value());
    REQUIRE(!(*monitor)->account_terminal_output(
        static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())
    ));
    REQUIRE(!(*monitor)->account_terminal_output(1));
    (*monitor)->finish();
    const auto snapshot = (*monitor)->snapshot();
    REQUIRE(snapshot.terminal_output_bytes == std::numeric_limits<std::uint64_t>::max());
    REQUIRE(snapshot.forced_cause == resource_termination_cause::supervisor_error);
    REQUIRE(snapshot.termination_callback_failed);
    return 0;
}

auto run() -> int {
    REQUIRE(!wall_output_monitor::create(0, 1, [](resource_termination_cause) {}).has_value());
    REQUIRE(!wall_output_monitor::create(1, 0, [](resource_termination_cause) {}).has_value());
    REQUIRE(!wall_output_monitor::create(
                 std::numeric_limits<std::uint64_t>::max(), 1, [](resource_termination_cause) {}
    ).has_value());
    REQUIRE(wall_deadline_test() == 0);
    REQUIRE(finish_cancels_deadline_test() == 0);
    REQUIRE(output_budget_test() == 0);
    REQUIRE(concurrent_output_test() == 0);
    REQUIRE(external_cause_arbitration_test() == 0);
    REQUIRE(saturation_and_callback_failure_test() == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
