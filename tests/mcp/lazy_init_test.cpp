// Lazy-init decorator: validates that initialize() runs at most once across
// any combination of explicit and implicit triggers, and that the cached
// server_info is returned on repeat explicit calls.

#include "glove/mcp/client.hpp"
#include "glove/mcp/lazy_init.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"

#include <atomic>
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

std::atomic<int> initialize_calls{0};
std::atomic<int> tools_list_calls{0};
std::atomic<int> tools_call_calls{0};

auto fake_server(std::string_view req) -> std::optional<std::string> {
    if (req.find("\"method\":\"initialize\"") != std::string_view::npos) {
        initialize_calls.fetch_add(1, std::memory_order_relaxed);
        return std::string{R"({"jsonrpc":"2.0","id":1,"result":{)"
                           R"("protocolVersion":"2024-11-05",)"
                           R"("serverInfo":{"name":"f","version":"0"},)"
                           R"("capabilities":{}}})"};
    }
    if (req.find("notifications/initialized") != std::string_view::npos) {
        return std::nullopt;
    }
    if (req.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        tools_list_calls.fetch_add(1, std::memory_order_relaxed);
        return std::string{R"({"jsonrpc":"2.0","id":2,"result":{"tools":[]}})"};
    }
    if (req.find("\"method\":\"tools/call\"") != std::string_view::npos) {
        tools_call_calls.fetch_add(1, std::memory_order_relaxed);
        return std::string{R"({"jsonrpc":"2.0","id":3,"result":{)"
                           R"("content":[{"type":"text","text":"ok"}],"isError":false}})"};
    }
    return std::string{R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"x"}})"};
}

auto run_implicit_first() -> int {
    initialize_calls.store(0);
    tools_list_calls.store(0);
    tools_call_calls.store(0);

    auto inner = glove::mcp::make_client(glove::mcp::make_in_memory_transport(fake_server));
    auto client = glove::mcp::make_lazy_init_client(std::move(inner), "g", "0");

    REQUIRE(client->list_tools().has_value());
    REQUIRE(initialize_calls.load() == 1);
    REQUIRE(tools_list_calls.load() == 1);

    REQUIRE(client->call_tool({.name = "x", .arguments_json = "{}"}).has_value());
    REQUIRE(initialize_calls.load() == 1); // still one
    REQUIRE(tools_call_calls.load() == 1);

    REQUIRE(client->list_tools().has_value());
    REQUIRE(initialize_calls.load() == 1);
    REQUIRE(tools_list_calls.load() == 2);
    return 0;
}

auto run_explicit_first() -> int {
    initialize_calls.store(0);
    tools_list_calls.store(0);

    auto inner = glove::mcp::make_client(glove::mcp::make_in_memory_transport(fake_server));
    auto client = glove::mcp::make_lazy_init_client(std::move(inner), "g", "0");

    auto info1 = client->initialize("", "");
    REQUIRE(info1.has_value());
    REQUIRE(info1->name == "f");
    REQUIRE(initialize_calls.load() == 1);

    auto info2 = client->initialize("", "");
    REQUIRE(info2.has_value());
    REQUIRE(info2->name == "f");
    REQUIRE(initialize_calls.load() == 1); // cached

    REQUIRE(client->list_tools().has_value());
    REQUIRE(initialize_calls.load() == 1);
    REQUIRE(tools_list_calls.load() == 1);
    return 0;
}

} // namespace

auto main() -> int {
    if (run_implicit_first() != 0) {
        return 1;
    }
    if (run_explicit_first() != 0) {
        return 1;
    }
    return 0;
}
