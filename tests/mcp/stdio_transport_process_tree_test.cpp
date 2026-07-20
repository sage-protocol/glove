// Destroying an upstream transport must terminate the upstream's whole
// process group, including helpers that ignore SIGTERM.

#include "glove/mcp/stdio_transport.hpp"

#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>
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
    ::pid_t descendant = -1;
    {
        glove::mcp::stdio_child_options opts{
            .program = "/bin/sh",
            .args =
                {
                    "/bin/sh",
                    "-c",
                    "trap '' TERM; sleep 30 & printf '%s\\n' \"$!\"; while :; do sleep 1; done",
                },
            .environment = {},
        };
        auto transport = glove::mcp::make_stdio_transport(opts);
        REQUIRE(transport.has_value());
        auto pid_line = (*transport)->recv();
        REQUIRE(pid_line.has_value());
        char* end = nullptr;
        const long parsed = std::strtol(pid_line->c_str(), &end, 10);
        REQUIRE(end != pid_line->c_str());
        REQUIRE(*end == '\0');
        REQUIRE(parsed > 1);
        descendant = static_cast<::pid_t>(parsed);
        REQUIRE(::kill(descendant, 0) == 0);
    }

    for (int attempt = 0; attempt < 100; ++attempt) {
        if (::kill(descendant, 0) < 0 && errno == ESRCH) {
            return 0;
        }
        ::usleep(10 * 1000);
    }
    (void)::kill(descendant, SIGKILL);
    std::fprintf(stderr, "upstream descendant %d survived transport destruction\n", descendant);
    return 1;
}

} // namespace

auto main() -> int {
    return run();
}
