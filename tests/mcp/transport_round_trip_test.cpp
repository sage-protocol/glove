// Drives an in_memory_transport through the codec-free stub client. What we
// validate here is that frame round-trips cleanly under ASan/TSan and that
// std::expected error propagation works at the boundary, independent of any
// JSON dialect.

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/testing.hpp"
#include "glove/mcp/transport.hpp"

#include <atomic>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    std::atomic<int> handler_calls{0};
    auto handler = [&handler_calls](std::string_view frame) -> std::optional<std::string> {
        handler_calls.fetch_add(1, std::memory_order_relaxed);
        std::string echo = "echo:";
        echo.append(frame);
        return echo;
    };

    auto t = glove::mcp::make_in_memory_transport(handler);
    auto c = glove::mcp::testing::make_stub_client_for_tests(std::move(t));

    auto tools = c->list_tools();
    REQUIRE(!tools.has_value());
    REQUIRE(tools.error().find("echo:list_tools") != std::string::npos);

    glove::mcp::tool_call_request req{.name = "noop", .arguments_json = "{}"};
    auto result = c->call_tool(req);
    REQUIRE(result.has_value());
    REQUIRE(result->status == glove::mcp::tool_call_status::transport_error);
    REQUIRE(result->error_message.find("echo:call_tool noop") != std::string::npos);

    REQUIRE(handler_calls.load() == 2);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
