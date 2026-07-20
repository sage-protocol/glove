#include "linux_process_identity.hpp"

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    char original_name[16]{};
    REQUIRE(::prctl(PR_GET_NAME, original_name) == 0);
    REQUIRE(::prctl(PR_SET_NAME, "glove ) probe") == 0);
    auto identity = glove::control::linux_detail::capture_linux_process_identity(::getpid());
    REQUIRE(::prctl(PR_SET_NAME, original_name) == 0);
    REQUIRE(identity.has_value());
    REQUIRE(identity->schema_version == 1);
    REQUIRE(identity->pid == static_cast<std::uint32_t>(::getpid()));
    REQUIRE(identity->boot_id.size() == 36);
    REQUIRE(identity->start_time_ticks > 0);
    REQUIRE(identity->cgroup_device > 0);
    REQUIRE(identity->cgroup_inode > 0);
    REQUIRE(identity->cgroup_path_digest.size() == 64);

    auto exact = glove::control::linux_detail::observe_linux_process_identity(*identity);
    REQUIRE(exact.has_value());
    REQUIRE(*exact == glove::control::linux_detail::linux_process_identity_observation::exact);

    auto changed = *identity;
    ++changed.start_time_ticks;
    auto mismatch = glove::control::linux_detail::observe_linux_process_identity(changed);
    REQUIRE(mismatch.has_value());
    REQUIRE(
        *mismatch == glove::control::linux_detail::linux_process_identity_observation::mismatch
    );

    auto invalid = *identity;
    invalid.cgroup_path_digest = "not-a-digest";
    REQUIRE(!glove::control::linux_detail::observe_linux_process_identity(invalid).has_value());

    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    REQUIRE(::pipe2(ready, O_CLOEXEC) == 0);
    REQUIRE(::pipe2(release, O_CLOEXEC) == 0);
    const auto child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        (void)::close(ready[0]);
        (void)::close(release[1]);
        const char value = '1';
        char child_release = 0;
        if (::write(ready[1], &value, 1) != 1 || ::read(release[0], &child_release, 1) != 1) {
            ::_exit(2);
        }
        ::_exit(0);
    }
    REQUIRE(::close(ready[1]) == 0);
    REQUIRE(::close(release[0]) == 0);
    char value = 0;
    REQUIRE(::read(ready[0], &value, 1) == 1);
    auto child_identity = glove::control::linux_detail::capture_linux_process_identity(child);
    REQUIRE(child_identity.has_value());
    REQUIRE(::write(release[1], &value, 1) == 1);
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
    REQUIRE(::close(ready[0]) == 0);
    REQUIRE(::close(release[1]) == 0);
    auto missing = glove::control::linux_detail::observe_linux_process_identity(*child_identity);
    REQUIRE(missing.has_value());
    REQUIRE(*missing == glove::control::linux_detail::linux_process_identity_observation::absent);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
