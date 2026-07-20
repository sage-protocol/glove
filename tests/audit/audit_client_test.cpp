// audit_client decorator: verifies one event per call, latency populated,
// status mapped correctly for both happy and error paths.

#include "glove/audit/audit_client.hpp"
#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
#include <expected>
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

class failing_sink final : public glove::audit::sink {
public:
    auto record(const glove::audit::event&) -> std::expected<void, std::string> override {
        return std::unexpected(std::string{"disk full"});
    }
};

auto fake_server(std::string_view req) -> std::optional<std::string> {
    if (req.find("\"method\":\"initialize\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":1,"result":{)"
                           R"("protocolVersion":"2024-11-05",)"
                           R"("serverInfo":{"name":"f","version":"0"},)"
                           R"("capabilities":{}}})"};
    }
    if (req.find("notifications/initialized") != std::string_view::npos) {
        return std::nullopt;
    }
    if (req.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":2,"result":{"tools":[)"
                           R"({"name":"echo","description":"","inputSchema":{}}]}})"};
    }
    if (req.find("\"name\":\"echo\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":3,"result":{)"
                           R"("content":[{"type":"text","text":"ok"}],"isError":false}})"};
    }
    if (req.find("\"name\":\"boom\"") != std::string_view::npos) {
        return std::string{R"({"jsonrpc":"2.0","id":4,"result":{)"
                           R"("content":[{"type":"text","text":"oops"}],"isError":true}})"};
    }
    return std::string{R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"x"}})"};
}

auto run() -> int {
    auto sink = glove::audit::make_memory_sink();
    auto inner_transport = glove::mcp::make_in_memory_transport(fake_server);
    auto inner = glove::mcp::make_client(std::move(inner_transport));
    auto client = glove::audit::make_audit_client(std::move(inner), sink);

    REQUIRE(client->initialize("g", "0").has_value());
    REQUIRE(client->list_tools().has_value());
    REQUIRE(client->call_tool({.name = "echo", .arguments_json = "{}"}).has_value());
    auto failed = client->call_tool({.name = "boom", .arguments_json = "{}"});
    REQUIRE(failed.has_value());
    REQUIRE(failed->status == glove::mcp::tool_call_status::execution_error);

    auto events = sink->take();
    REQUIRE(events.size() == 4);

    REQUIRE(events[0].what == glove::audit::action::initialize);
    REQUIRE(events[0].status == glove::mcp::tool_call_status::ok);

    REQUIRE(events[1].what == glove::audit::action::list_tools);
    REQUIRE(events[1].status == glove::mcp::tool_call_status::ok);

    REQUIRE(events[2].what == glove::audit::action::call_tool);
    REQUIRE(events[2].tool_name == "echo");
    REQUIRE(events[2].status == glove::mcp::tool_call_status::ok);

    REQUIRE(events[3].what == glove::audit::action::call_tool);
    REQUIRE(events[3].tool_name == "boom");
    REQUIRE(events[3].status == glove::mcp::tool_call_status::execution_error);

    // Latencies are non-negative; not asserting positive because the in-memory
    // path can finish below clock resolution.
    for (const auto& e : events) {
        REQUIRE(e.latency.count() >= 0);
    }

    // Audit is part of the security boundary: a failed append must fail the
    // operation instead of silently creating an unaudited gap.
    auto failing_transport = glove::mcp::make_in_memory_transport(fake_server);
    auto failing_inner = glove::mcp::make_client(std::move(failing_transport));
    auto failing_client =
        glove::audit::make_audit_client(std::move(failing_inner), std::make_shared<failing_sink>());
    auto unaudited = failing_client->initialize("g", "0");
    REQUIRE(!unaudited.has_value());
    REQUIRE(unaudited.error().find("disk full") != std::string::npos);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
