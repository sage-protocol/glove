// Validates the policy_client decorator end-to-end:
//   - list_tools is filtered through the engine
//   - call_tool denies disallowed tools without touching the transport
//   - call_tool forwards allowed tools to the inner client unchanged

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"
#include "glove/policy/engine.hpp"
#include "glove/policy/policy_client.hpp"

#include <atomic>
#include <cstdio>
#include <memory>
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

std::atomic<int> transport_calls{0};

auto fake_server(std::string_view req) -> std::optional<std::string> {
    transport_calls.fetch_add(1, std::memory_order_relaxed);
    if (req.find("\"method\":\"initialize\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":1,"result":{)"
                           R"("protocolVersion":"2024-11-05",)"
                           R"("serverInfo":{"name":"fake","version":"0"},)"
                           R"("capabilities":{}}})"};
    }
    if (req.find("notifications/initialized") != std::string_view::npos) {
        return std::nullopt;
    }
    if (req.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":2,"result":{"tools":[)"
                           R"({"name":"echo","description":"","inputSchema":{}},)"
                           R"({"name":"rm","description":"","inputSchema":{}},)"
                           R"({"name":"grep","description":"","inputSchema":{}}]}})"};
    }
    if (req.find("\"method\":\"tools/call\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":3,"result":{)"
                           R"("content":[{"type":"text","text":"ok"}],"isError":false}})"};
    }
    return std::string{R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"x"}})"};
}

auto run() -> int {
    glove::policy::allow_list_options opts{
        .allow = {"echo", "grep"},
        .deny = {},
        .default_decision = glove::policy::decision::deny,
    };
    std::shared_ptr<glove::policy::engine> eng =
        glove::policy::make_allow_list_engine(std::move(opts));

    auto transport = glove::mcp::make_in_memory_transport(fake_server);
    auto inner = glove::mcp::make_client(std::move(transport));
    auto client = glove::policy::make_policy_client(std::move(inner), eng);

    auto info = client->initialize("glove-policy", "0.0.1");
    REQUIRE(info.has_value());

    auto tools = client->list_tools();
    REQUIRE(tools.has_value());
    REQUIRE(tools->size() == 2);
    REQUIRE((*tools)[0].name == "echo");
    REQUIRE((*tools)[1].name == "grep");

    // Allowed call: forwarded to transport.
    int calls_before_allowed = transport_calls.load();
    auto allowed = client->call_tool({.name = "echo", .arguments_json = "{}"});
    REQUIRE(allowed.has_value());
    REQUIRE(allowed->status == glove::mcp::tool_call_status::ok);
    REQUIRE(allowed->content == "ok");
    REQUIRE(transport_calls.load() > calls_before_allowed);

    // Denied call: no transport contact.
    int calls_before_denied = transport_calls.load();
    auto denied = client->call_tool({.name = "rm", .arguments_json = "{}"});
    REQUIRE(denied.has_value());
    REQUIRE(denied->status == glove::mcp::tool_call_status::invalid_arguments);
    REQUIRE(denied->error_message.find("policy denied") != std::string::npos);
    REQUIRE(transport_calls.load() == calls_before_denied);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
