// End-to-end smoke against a real MCP server: yams.
//
// Spawns `yams serve --quiet` over the stdio transport, runs the initialize
// handshake, calls tools/list, and asserts that yams advertises its built-in
// `mcp.echo` tool. This is the first test in the project that exercises the
// full pipeline against a third-party MCP server, validating that the line
// framing + JSON-RPC + glaze codec match a real server's wire format.
//
// Built only when CMake found yams on PATH at configure time; the binary path
// is supplied via GLOVE_YAMS_BIN.

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>

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

    auto info = client->initialize("glove-yams-smoke", "0.0.1");
    if (!info) {
        std::fprintf(stderr, "initialize failed: %s\n", info.error().c_str());
        return 1;
    }
    REQUIRE(info->name == "yams-mcp");
    REQUIRE(!info->version.empty());
    // Don't lock to a specific protocolVersion: the server may negotiate
    // either its own (2024-11-05) or echo the one we advertised. Accept any
    // non-empty value — the codec already validates it against our supported
    // set in parse_initialize_result.
    REQUIRE(!info->protocol_version.empty());

    auto tools = client->list_tools();
    if (!tools) {
        std::fprintf(stderr, "list_tools failed: %s\n", tools.error().c_str());
        return 1;
    }
    REQUIRE(!tools->empty());

    bool found_echo = std::any_of(tools->begin(), tools->end(), [](const auto& t) {
        return t.name == "mcp.echo";
    });
    REQUIRE(found_echo);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
