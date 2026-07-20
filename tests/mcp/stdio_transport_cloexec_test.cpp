// Regression test for F1: the parent-side ends of an upstream's pipes must be
// close-on-exec so they do NOT survive into a subsequently spawned process.
// If they leaked, a contained agent could read/write upstream MCP servers
// directly, bypassing the kernel's policy and audit.
//
// Strategy: hold several upstreams open (each contributes two parent-side pipe
// fds), then spawn one more process that reports how many file descriptors it
// inherited. With FD_CLOEXEC the count is constant (just stdio + the listing's
// own handle); without it, the count grows by two per held upstream.

#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    // Hold several upstreams open. Each is a plain `cat` that we never talk to;
    // we only care about the parent-side fds make_stdio_transport keeps.
    std::vector<std::unique_ptr<glove::mcp::transport>> held;
    for (int i = 0; i < 4; ++i) {
        glove::mcp::stdio_child_options opts{
            .program = "/bin/cat",
            .args = {"cat"},
        };
        auto t_or = glove::mcp::make_stdio_transport(opts);
        REQUIRE(t_or.has_value());
        held.push_back(std::move(*t_or));
    }

    // Now spawn a counter through the same primitive. It prints how many
    // entries are in /dev/fd, i.e. how many fds it actually inherited.
    glove::mcp::stdio_child_options counter{
        .program = "/bin/sh",
        .args = {"sh", "-c", "ls /dev/fd | wc -l"},
    };
    auto c_or = glove::mcp::make_stdio_transport(counter);
    REQUIRE(c_or.has_value());
    std::unique_ptr<glove::mcp::transport> c = std::move(*c_or);

    auto line = c->recv();
    REQUIRE(line.has_value());
    const int count = std::atoi(line->c_str());

    // With CLOEXEC the counter inherits only its own stdio (0,1,2) plus the
    // descriptor `ls` opens to read the directory — a handful. Without the fix
    // it would also inherit 8 leaked upstream fds, pushing the count past 6.
    std::fprintf(stderr, "inherited fd count: %d\n", count);
    REQUIRE(count > 0);
    REQUIRE(count <= 6);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
