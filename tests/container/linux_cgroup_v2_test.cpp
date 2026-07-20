#include "cgroup_v2.hpp"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#ifndef GLOVE_CGROUP_PROBE_AGENT_BIN
#    error "GLOVE_CGROUP_PROBE_AGENT_BIN must point at the cgroup probe agent"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto stopped_probe(const char* mode, const char* argument = nullptr) -> ::pid_t {
    const ::pid_t child = ::fork();
    if (child == 0) {
        ::raise(SIGSTOP);
        if (argument == nullptr) {
            ::execl(GLOVE_CGROUP_PROBE_AGENT_BIN, GLOVE_CGROUP_PROBE_AGENT_BIN, mode, nullptr);
        } else {
            ::execl(
                GLOVE_CGROUP_PROBE_AGENT_BIN, GLOVE_CGROUP_PROBE_AGENT_BIN, mode, argument, nullptr
            );
        }
        std::_Exit(50);
    }
    return child;
}

auto wait_stopped(::pid_t child) -> bool {
    int status = 0;
    while (::waitpid(child, &status, WUNTRACED) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    return WIFSTOPPED(status);
}

auto read_trimmed(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path};
    std::string value;
    std::getline(input, value);
    return value;
}

auto run_pid_limit_test(glove::container::linux_detail::cgroup_v2_root& root) -> int {
    glove::container::resource_limits limits{
        .cpu_time_ms = 10'000,
        .memory_bytes = 256U * 1024U * 1024U,
        .pids = 2,
        .wall_time_ms = 10'000,
        .disk_bytes = 16U * 1024U * 1024U,
        .terminal_output_bytes = 1024U * 1024U,
    };
    auto session = root.create_session("pid-limit", limits);
    REQUIRE(session.has_value());
    REQUIRE(read_trimmed(session->path() / "memory.max") == std::to_string(limits.memory_bytes));
    REQUIRE(read_trimmed(session->path() / "memory.swap.max") == "0");
    REQUIRE(read_trimmed(session->path() / "pids.max") == "2");

    const ::pid_t child = stopped_probe("pids");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    REQUIRE(session->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
    auto observation = session->observe();
    REQUIRE(observation.has_value());
    REQUIRE(observation->peak_pids == 2);
    REQUIRE(observation->pid_limit_hit);
    REQUIRE(session->cleanup().has_value());
    return 0;
}

auto run_memory_limit_test(glove::container::linux_detail::cgroup_v2_root& root) -> int {
    constexpr std::size_t memory_limit = 96U * 1024U * 1024U;
    constexpr const char* allocation_size = "402653184";
    glove::container::resource_limits limits{
        .cpu_time_ms = 10'000,
        .memory_bytes = memory_limit,
        .pids = 2,
        .wall_time_ms = 10'000,
        .disk_bytes = 16U * 1024U * 1024U,
        .terminal_output_bytes = 1024U * 1024U,
    };
    auto oom_session = root.create_session("memory-oom", limits);
    REQUIRE(oom_session.has_value());
    const ::pid_t allocator = stopped_probe("memory", allocation_size);
    REQUIRE(allocator > 0);
    REQUIRE(wait_stopped(allocator));
    REQUIRE(oom_session->attach(allocator).has_value());
    REQUIRE(::kill(allocator, SIGCONT) == 0);
    int status = 0;
    REQUIRE(::waitpid(allocator, &status, 0) == allocator);
    REQUIRE(WIFSIGNALED(status));
    REQUIRE(WTERMSIG(status) == SIGKILL);
    auto observation = oom_session->observe();
    REQUIRE(observation.has_value());
    REQUIRE(observation->peak_memory_bytes > 0);
    REQUIRE(observation->memory_limit_hit);
    REQUIRE(oom_session->cleanup().has_value());
    return 0;
}

auto run_cpu_limit_test(glove::container::linux_detail::cgroup_v2_root& root) -> int {
    glove::container::resource_limits limits{
        .cpu_time_ms = 25,
        .memory_bytes = 256U * 1024U * 1024U,
        .pids = 1,
        .wall_time_ms = 10'000,
        .disk_bytes = 16U * 1024U * 1024U,
        .terminal_output_bytes = 1024U * 1024U,
    };
    auto session = root.create_session("cpu-limit", limits);
    REQUIRE(session.has_value());
    const ::pid_t child = stopped_probe("cpu");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    REQUIRE(session->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    bool triggered = false;
    for (unsigned int attempt = 0; attempt < 2'000; ++attempt) {
        auto event = session->triggered_limit(limits);
        REQUIRE(event.has_value());
        if (*event == glove::container::linux_detail::cgroup_limit_event::cpu_time) {
            triggered = true;
            break;
        }
        ::usleep(1'000);
    }
    REQUIRE(triggered);
    REQUIRE(session->kill_all().has_value());
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFSIGNALED(status));
    REQUIRE(WTERMSIG(status) == SIGKILL);
    auto observation = session->observe();
    REQUIRE(observation.has_value());
    REQUIRE(observation->cpu_time_ms >= limits.cpu_time_ms);
    REQUIRE(session->cleanup().has_value());
    return 0;
}

auto run_crash_adoption_test(glove::container::linux_detail::cgroup_v2_root& root) -> int {
    int identity_pipe[2]{};
    REQUIRE(::pipe(identity_pipe) == 0);
    const ::pid_t owner = ::fork();
    REQUIRE(owner >= 0);
    if (owner == 0) {
        ::close(identity_pipe[0]);
        const glove::container::resource_limits limits{
            .cpu_time_ms = 10'000,
            .memory_bytes = 64U * 1024U * 1024U,
            .pids = 2,
            .wall_time_ms = 10'000,
            .disk_bytes = 16U * 1024U * 1024U,
            .terminal_output_bytes = 1024U * 1024U,
        };
        auto session = root.create_session("crash-adoption", limits);

        struct stat status{};

        if (!session || ::fstat(session->directory_fd(), &status) != 0 || status.st_dev == 0 ||
            status.st_ino == 0) {
            std::_Exit(40);
        }
        const std::uint64_t identity[] = {
            static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
        };
        if (::write(identity_pipe[1], identity, sizeof(identity)) != sizeof(identity)) {
            std::_Exit(41);
        }
        std::_Exit(0);
    }
    ::close(identity_pipe[1]);
    std::uint64_t identity[2]{};
    REQUIRE(::read(identity_pipe[0], identity, sizeof(identity)) == sizeof(identity));
    ::close(identity_pipe[0]);
    int owner_status = 0;
    REQUIRE(::waitpid(owner, &owner_status, 0) == owner);
    REQUIRE(WIFEXITED(owner_status));
    REQUIRE(WEXITSTATUS(owner_status) == 0);

    REQUIRE(!root.adopt_session("crash-adoption", identity[0], identity[1] + 1U).has_value());
    auto adopted = root.adopt_session("crash-adoption", identity[0], identity[1]);
    REQUIRE(adopted.has_value());

    struct stat adopted_status{};

    REQUIRE(::fstat(adopted->directory_fd(), &adopted_status) == 0);
    REQUIRE(static_cast<std::uint64_t>(adopted_status.st_dev) == identity[0]);
    REQUIRE(static_cast<std::uint64_t>(adopted_status.st_ino) == identity[1]);
    REQUIRE(adopted->cleanup().has_value());
    REQUIRE(!root.adopt_session("crash-adoption", identity[0], identity[1]).has_value());
    REQUIRE(
        root.cleanup_session_if_matches("crash-adoption", identity[0], identity[1]).has_value()
    );
    return 0;
}

auto run() -> int {
    auto root = glove::container::linux_detail::cgroup_v2_root::prepare_for_current_process();
    if (!root) {
        std::fprintf(
            stderr,
            "cgroup v2 delegation unavailable in this test topology: %s\n",
            root.error().c_str()
        );
        return 77;
    }
    glove::container::resource_limits limits{
        .cpu_time_ms = 1,
        .memory_bytes = 1,
        .pids = 1,
        .wall_time_ms = 1,
        .disk_bytes = 1,
        .terminal_output_bytes = 1,
    };
    REQUIRE(!root->create_session("../escape", limits).has_value());
    REQUIRE(run_pid_limit_test(*root) == 0);
    REQUIRE(run_memory_limit_test(*root) == 0);
    REQUIRE(run_cpu_limit_test(*root) == 0);
    REQUIRE(run_crash_adoption_test(*root) == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
