#include "glove/mcp/client.hpp"

#include "glove/mcp/messages.hpp"
#include "glove/mcp/testing.hpp"
#include "glove/mcp/transport.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::mcp::testing {

namespace {

// Stub client: drives the transport but performs no codec work. Returns
// transport_error so callers can validate plumbing without committing to a
// JSON dialect.
class stub_client final : public client {
public:
    explicit stub_client(std::unique_ptr<transport> t) : transport_{std::move(t)} {}

    auto initialize(std::string_view, std::string_view)
        -> std::expected<server_info, std::string> override {
        return server_info{.name = "stub", .version = "0.0.0", .protocol_version = "n/a"};
    }

    auto list_tools() -> std::expected<std::vector<tool_descriptor>, std::string> override {
        if (auto sent = transport_->send("list_tools"); !sent) {
            return std::unexpected(sent.error());
        }
        auto frame = transport_->recv();
        if (!frame) {
            return std::unexpected(frame.error());
        }
        return std::unexpected(std::string{"codec not yet wired; got frame: "} + *frame);
    }

    auto call_tool(const tool_call_request& req)
        -> std::expected<tool_call_result, std::string> override {
        std::string probe = "call_tool ";
        probe.append(req.name);
        if (auto sent = transport_->send(probe); !sent) {
            return std::unexpected(sent.error());
        }
        auto frame = transport_->recv();
        if (!frame) {
            return std::unexpected(frame.error());
        }
        return tool_call_result{
            .status = tool_call_status::transport_error,
            .content = {},
            .structured_json = {},
            .error_message = "codec not yet wired; got frame: " + *frame,
        };
    }

private:
    std::unique_ptr<transport> transport_;
};

} // namespace

auto make_stub_client_for_tests(std::unique_ptr<transport> t) -> std::unique_ptr<client> {
    return std::make_unique<stub_client>(std::move(t));
}

} // namespace glove::mcp::testing
