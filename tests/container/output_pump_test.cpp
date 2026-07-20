#include "output_pump.hpp"
#include "resource_monitor.hpp"

#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
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
using glove::container::detail::output_pump;
using glove::container::detail::output_pump_options;
using glove::container::detail::wall_output_monitor;

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

using owned_pipe = std::array<unique_fd, 2>;

auto make_pipe() -> std::expected<owned_pipe, std::string> {
    std::array<int, 2> raw = {-1, -1};
    if (::pipe(raw.data()) != 0) {
        return std::unexpected(std::string{"pipe failed"});
    }
    return owned_pipe{unique_fd{raw[0]}, unique_fd{raw[1]}};
}

auto write_all(int fd, std::string_view bytes) -> bool {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ::ssize_t written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (written <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

auto make_pump(
    owned_pipe& stdout_pipe,
    owned_pipe& stderr_pipe,
    std::shared_ptr<wall_output_monitor> monitor = {},
    std::size_t max_frame_bytes = 1024,
    std::size_t max_queued_bytes = 1024,
    output_pump_options::stderr_callback stderr_sink = {}
) -> std::expected<std::unique_ptr<output_pump>, std::string> {
    auto pump = output_pump::create({
        .stdout_fd = stdout_pipe[0].get(),
        .stderr_fd = stderr_pipe[0].get(),
        .max_frame_bytes = max_frame_bytes,
        .max_queued_bytes = max_queued_bytes,
        .monitor = std::move(monitor),
        .stderr_sink = std::move(stderr_sink),
    });
    if (pump) {
        static_cast<void>(stdout_pipe[0].release());
        static_cast<void>(stderr_pipe[0].release());
    }
    return pump;
}

auto drains_without_consumer_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());

    std::mutex mutex;
    std::condition_variable changed;
    unsigned int terminations = 0;
    auto monitor = wall_output_monitor::create(2'000, 10, [&](resource_termination_cause cause) {
        std::lock_guard lock{mutex};
        if (cause == resource_termination_cause::terminal_output_limit) {
            ++terminations;
        }
        changed.notify_all();
    });
    REQUIRE(monitor.has_value());
    auto pump = make_pump(*stdout_pipe, *stderr_pipe, *monitor);
    REQUIRE(pump.has_value());

    REQUIRE(write_all((*stdout_pipe)[1].get(), "alpha\n"));
    REQUIRE(write_all((*stderr_pipe)[1].get(), "123456"));
    {
        std::unique_lock lock{mutex};
        REQUIRE(changed.wait_for(lock, std::chrono::seconds{2}, [&] { return terminations == 1; }));
    }
    (*pump)->stop();
    (*monitor)->finish();
    const auto snapshot = (*monitor)->snapshot();
    REQUIRE(snapshot.terminal_output_bytes == 12);
    REQUIRE(snapshot.forced_cause == resource_termination_cause::terminal_output_limit);
    return 0;
}

auto bounded_queue_still_drains_stderr_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());

    std::mutex sink_mutex;
    std::condition_variable sink_changed;
    std::string stderr_output;
    auto sink = [&](std::string_view bytes) {
        std::lock_guard lock{sink_mutex};
        stderr_output.append(bytes);
        sink_changed.notify_all();
    };
    auto pump = make_pump(*stdout_pipe, *stderr_pipe, {}, 32, 8, sink);
    REQUIRE(pump.has_value());
    REQUIRE(write_all((*stdout_pipe)[1].get(), "one\ntwo\nthree\n"));
    REQUIRE(write_all((*stderr_pipe)[1].get(), "diagnostic"));
    {
        std::unique_lock lock{sink_mutex};
        REQUIRE(sink_changed.wait_for(lock, std::chrono::seconds{2}, [&] {
            return stderr_output == "diagnostic";
        }));
    }
    auto frame = (*pump)->recv_frame();
    REQUIRE(frame == "one");
    frame = (*pump)->recv_frame();
    REQUIRE(frame == "two");
    frame = (*pump)->recv_frame();
    REQUIRE(frame == "three");
    (*pump)->stop();
    return 0;
}

auto oversized_frame_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());
    auto pump = make_pump(*stdout_pipe, *stderr_pipe, {}, 4, 8);
    REQUIRE(pump.has_value());
    REQUIRE(write_all((*stdout_pipe)[1].get(), "12345"));
    auto frame = (*pump)->recv_frame();
    REQUIRE(!frame.has_value());
    REQUIRE(frame.error().find("max_frame_bytes") != std::string::npos);
    (*pump)->stop();
    return 0;
}

auto stop_unblocks_receiver_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());
    auto pump = make_pump(*stdout_pipe, *stderr_pipe);
    REQUIRE(pump.has_value());

    std::mutex mutex;
    std::condition_variable changed;
    bool started = false;
    std::optional<std::expected<std::string, std::string>> result;
    std::thread receiver{[&] {
        {
            std::lock_guard lock{mutex};
            started = true;
            changed.notify_all();
        }
        auto frame = (*pump)->recv_frame();
        {
            std::lock_guard lock{mutex};
            result = std::move(frame);
            changed.notify_all();
        }
    }};
    {
        std::unique_lock lock{mutex};
        REQUIRE(changed.wait_for(lock, std::chrono::seconds{2}, [&] { return started; }));
    }
    (*pump)->stop();
    receiver.join();
    REQUIRE(result.has_value());
    REQUIRE(!result->has_value());
    REQUIRE(result->error().find("stopped") != std::string::npos);
    return 0;
}

auto stop_discards_queued_frames_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());

    std::mutex mutex;
    std::condition_variable changed;
    bool stderr_drained = false;
    auto sink = [&](std::string_view) {
        std::lock_guard lock{mutex};
        stderr_drained = true;
        changed.notify_all();
    };
    auto pump = make_pump(*stdout_pipe, *stderr_pipe, {}, 32, 32, sink);
    REQUIRE(pump.has_value());
    REQUIRE(write_all((*stdout_pipe)[1].get(), "queued\n"));
    REQUIRE(write_all((*stderr_pipe)[1].get(), "barrier"));
    {
        std::unique_lock lock{mutex};
        REQUIRE(changed.wait_for(lock, std::chrono::seconds{2}, [&] { return stderr_drained; }));
    }
    (*pump)->stop();
    auto frame = (*pump)->recv_frame();
    REQUIRE(!frame.has_value());
    REQUIRE(frame.error().find("stopped") != std::string::npos);
    return 0;
}

auto discard_stdout_drains_to_eof_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());

    std::string stderr_output;
    auto pump = output_pump::create({
        .stdout_fd = (*stdout_pipe)[0].get(),
        .stderr_fd = (*stderr_pipe)[0].get(),
        .max_frame_bytes = 1,
        .max_queued_bytes = 1,
        .discard_stdout = true,
        .monitor = {},
        .stderr_sink = [&](std::string_view bytes) { stderr_output.append(bytes); },
    });
    REQUIRE(pump.has_value());
    static_cast<void>((*stdout_pipe)[0].release());
    static_cast<void>((*stderr_pipe)[0].release());
    REQUIRE(write_all((*stdout_pipe)[1].get(), std::string(4096, 'x')));
    REQUIRE(write_all((*stderr_pipe)[1].get(), "diagnostic"));
    (*stdout_pipe)[1].reset();
    (*stderr_pipe)[1].reset();
    auto drained = (*pump)->finish_draining();
    REQUIRE(drained.has_value());
    REQUIRE(stderr_output == "diagnostic");
    return 0;
}

auto discard_stdout_reports_read_failure_test() -> int {
    auto stdout_pipe = make_pipe();
    auto stderr_pipe = make_pipe();
    REQUIRE(stdout_pipe.has_value());
    REQUIRE(stderr_pipe.has_value());
    auto pump = output_pump::create({
        .stdout_fd = (*stdout_pipe)[1].get(),
        .stderr_fd = (*stderr_pipe)[0].get(),
        .max_frame_bytes = 1,
        .max_queued_bytes = 1,
        .discard_stdout = true,
        .monitor = {},
        .stderr_sink = {},
    });
    REQUIRE(pump.has_value());
    static_cast<void>((*stdout_pipe)[1].release());
    static_cast<void>((*stderr_pipe)[0].release());
    (*stdout_pipe)[0].reset();
    (*stderr_pipe)[1].reset();
    auto drained = (*pump)->finish_draining();
    REQUIRE(!drained.has_value());
    REQUIRE(drained.error().find("read agent stdout") != std::string::npos);
    return 0;
}

auto run() -> int {
    REQUIRE(!output_pump::create({}).has_value());
    REQUIRE(drains_without_consumer_test() == 0);
    REQUIRE(bounded_queue_still_drains_stderr_test() == 0);
    REQUIRE(oversized_frame_test() == 0);
    REQUIRE(stop_unblocks_receiver_test() == 0);
    REQUIRE(stop_discards_queued_frames_test() == 0);
    REQUIRE(discard_stdout_drains_to_eof_test() == 0);
    REQUIRE(discard_stdout_reports_read_failure_test() == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
