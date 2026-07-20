// Regression test for F4: a peer that streams bytes without ever sending a
// newline must not be able to grow the recv buffer without bound. recv() is
// expected to fail with a frame-size error well before the host runs out of
// memory, rather than appending forever.

#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
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
    // Emit ~20 MiB of NUL bytes (no newline) then EOF. That is past the 16 MiB
    // cap, so recv() must error before consuming it all.
    glove::mcp::stdio_child_options opts{
        .program = "/bin/sh",
        .args = {"sh", "-c", "head -c 20971520 /dev/zero"},
    };
    auto t_or = glove::mcp::make_stdio_transport(opts);
    REQUIRE(t_or.has_value());
    std::unique_ptr<glove::mcp::transport> t = std::move(*t_or);

    auto got = t->recv();
    REQUIRE(!got.has_value());
    // Must fail *because of the cap*, not merely because the peer hit EOF after
    // we buffered the whole 20 MiB — that distinction is the regression guard.
    REQUIRE(got.error().find("max_frame_bytes") != std::string::npos);
    std::fprintf(stderr, "recv rejected oversized frame: %s\n", got.error().c_str());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
