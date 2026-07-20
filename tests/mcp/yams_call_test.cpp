// End-to-end tools/call smoke against yams. Spawns yams serve, runs the
// initialize handshake, then invokes the built-in mcp.echo tool and verifies
// the echoed content shows up in the response.

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"

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

    auto info = client->initialize("glove-yams-call", "0.0.1");
    if (!info) {
        std::fprintf(stderr, "initialize failed: %s\n", info.error().c_str());
        return 1;
    }

    glove::mcp::tool_call_request req{
        .name = "mcp.echo",
        .arguments_json = R"({"text":"glove-says-hi"})",
    };
    auto result = client->call_tool(req);
    if (!result) {
        std::fprintf(stderr, "call_tool failed: %s\n", result.error().c_str());
        return 1;
    }
    REQUIRE(result->status == glove::mcp::tool_call_status::ok);
    REQUIRE(result->content.find("glove-says-hi") != std::string::npos);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
