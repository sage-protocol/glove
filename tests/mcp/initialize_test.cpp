// initialize() handshake test against an in-memory fake server. Verifies that
// the client (a) sends a well-formed initialize request, (b) parses the
// returned server_info, and (c) follows up with the notifications/initialized
// notification — which the fake server must accept without queueing a
// response (otherwise the next list_tools call would read it as a stale
// frame).

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
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

std::atomic<int> notification_count{0};
std::atomic<int> initialize_count{0};
std::atomic<int> tools_list_count{0};

auto fake_server(std::string_view req) -> std::optional<std::string> {
    if (req.find("\"method\":\"initialize\"") != std::string_view::npos) {
        initialize_count.fetch_add(1, std::memory_order_relaxed);
        return std::string{R"({"jsonrpc":"2.0","id":1,"result":{)"
                           R"("protocolVersion":"2024-11-05",)"
                           R"("serverInfo":{"name":"fake-mcp","version":"1.2.3"},)"
                           R"("capabilities":{}}})"};
    }
    if (req.find("notifications/initialized") != std::string_view::npos) {
        notification_count.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt; // notification — no response
    }
    if (req.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        tools_list_count.fetch_add(1, std::memory_order_relaxed);
        return std::string{R"({"jsonrpc":"2.0","id":2,"result":{"tools":[)"
                           R"({"name":"x","description":"","inputSchema":{}}]}})"};
    }
    return std::string{R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"x"}})"};
}

auto run() -> int {
    auto transport = glove::mcp::make_in_memory_transport(fake_server);
    auto client = glove::mcp::make_client(std::move(transport));

    auto info = client->initialize("glove-test", "0.0.1");
    REQUIRE(info.has_value());
    REQUIRE(info->name == "fake-mcp");
    REQUIRE(info->version == "1.2.3");
    REQUIRE(info->protocol_version == "2024-11-05");
    REQUIRE(initialize_count.load() == 1);
    REQUIRE(notification_count.load() == 1);

    // The notification must not have left a stale frame: the next list_tools
    // call should pair cleanly with the tools/list response.
    auto tools = client->list_tools();
    REQUIRE(tools.has_value());
    REQUIRE(tools->size() == 1);
    REQUIRE((*tools)[0].name == "x");
    REQUIRE(tools_list_count.load() == 1);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
