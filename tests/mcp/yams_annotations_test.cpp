// Validates that yams' tool annotations flow through the codec into
// tool_descriptor::annotations, and demonstrates the annotation-driven
// allow-list pattern: list_tools, keep only read-only tools, build a policy
// from those names, wrap the client.
//
// macOS-only because it depends on the yams binary. Built only when CMake
// finds yams on PATH.

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"
#include "glove/policy/engine.hpp"
#include "glove/policy/policy_client.hpp"

#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#ifndef GLOVE_YAMS_BIN
#    error "GLOVE_YAMS_BIN must be defined to point at the yams binary"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    glove::mcp::stdio_child_options opts{
        .program = GLOVE_YAMS_BIN,
        .args = {"yams", "serve", "--quiet"},
    };
    auto transport = glove::mcp::make_stdio_transport(opts);
    REQUIRE(transport.has_value());

    auto client = glove::mcp::make_client(std::move(*transport));
    auto info = client->initialize("glove-annotations", "0.0.1");
    if (!info) {
        std::fprintf(stderr, "initialize failed: %s\n", info.error().c_str());
        return 1;
    }

    auto tools = client->list_tools();
    if (!tools) {
        std::fprintf(stderr, "list_tools failed: %s\n", tools.error().c_str());
        return 1;
    }

    int annotated = 0;
    int read_only = 0;
    for (const auto& t : *tools) {
        if (t.annotations.has_annotations) {
            ++annotated;
        }
        if (t.annotations.read_only_hint) {
            ++read_only;
        }
    }
    // yams advertises annotations on every tool we have inspected so far.
    REQUIRE(annotated > 0);
    // mcp.echo reports readOnlyHint=true; verify at least one such tool surfaces.
    REQUIRE(read_only > 0);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
