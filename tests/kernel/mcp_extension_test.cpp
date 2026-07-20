// MCP extension forwards tools()/invoke() to its wrapped mcp::client. We
// stand up a fake upstream via in_memory_transport + lazy_init_client so the
// initialize handshake is handled implicitly.

#include "glove/kernel/extension.hpp"
#include "glove/kernel/mcp_extension.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/lazy_init.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto fake_upstream(std::string_view req) -> std::optional<std::string> {
    if (req.find("\"method\":\"initialize\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":1,"result":{)"
                           R"("protocolVersion":"2025-06-18",)"
                           R"("serverInfo":{"name":"upstream","version":"1"},)"
                           R"("capabilities":{}}})"};
    }
    if (req.find("notifications/initialized") != std::string_view::npos) {
        return std::nullopt;
    }
    if (req.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":2,"result":{"tools":[)"
                           R"({"name":"hello","description":"","inputSchema":{}}]}})"};
    }
    if (req.find("\"method\":\"tools/call\"") != std::string_view::npos) {
        return std::string{
            R"({"jsonrpc":"2.0","id":3,"result":{)"
            R"("content":[{"type":"text","text":"upstream got it"}],"isError":false}})"
        };
    }
    return std::string{R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"x"}})"};
}

auto run() -> int {
    auto transport = glove::mcp::make_in_memory_transport(fake_upstream);
    auto client = glove::mcp::make_client(std::move(transport));
    auto lazy = glove::mcp::make_lazy_init_client(std::move(client), "glove-test", "0");
    auto ext = glove::kernel::make_mcp_extension("upstream", std::move(lazy));

    REQUIRE(ext->name() == "upstream");

    auto tools = ext->tools();
    REQUIRE(tools.has_value());
    REQUIRE(tools->size() == 1);
    REQUIRE((*tools)[0].name == "hello");

    auto result = ext->invoke("hello", R"({"x":1})");
    REQUIRE(result.has_value());
    REQUIRE(result->status == glove::mcp::tool_call_status::ok);
    REQUIRE(result->content == "upstream got it");

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
