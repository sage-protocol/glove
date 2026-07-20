#include "glove/audit/audit_client.hpp"

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"

#include <chrono>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::audit {

namespace {

class audit_client final : public glove::mcp::client {
public:
    audit_client(std::unique_ptr<glove::mcp::client> inner, std::shared_ptr<sink> s)
        : inner_{std::move(inner)}, sink_{std::move(s)} {}

    auto initialize(std::string_view client_name, std::string_view client_version)
        -> std::expected<glove::mcp::server_info, std::string> override {
        auto start = std::chrono::steady_clock::now();
        auto out = inner_->initialize(client_name, client_version);
        if (auto audited = emit(action::initialize, "", "", out.has_value(), error_of(out), start);
            !audited) {
            return std::unexpected(std::string{"audit: "} + audited.error());
        }
        return out;
    }

    auto list_tools()
        -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        auto start = std::chrono::steady_clock::now();
        auto out = inner_->list_tools();
        if (auto audited = emit(action::list_tools, "", "", out.has_value(), error_of(out), start);
            !audited) {
            return std::unexpected(std::string{"audit: "} + audited.error());
        }
        return out;
    }

    auto call_tool(const glove::mcp::tool_call_request& req)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        auto start = std::chrono::steady_clock::now();
        auto out = inner_->call_tool(req);

        event ev{
            .what = action::call_tool,
            .tool_name = req.name,
            .arguments_json = req.arguments_json,
            .status = out.has_value() ? out->status : glove::mcp::tool_call_status::transport_error,
            .error_message = out.has_value() ? out->error_message : out.error(),
            .at = std::chrono::system_clock::now(),
            .latency = std::chrono::steady_clock::now() - start,
        };
        if (auto audited = sink_->record(ev); !audited) {
            return std::unexpected(std::string{"audit: "} + audited.error());
        }
        return out;
    }

private:
    template<class T>
    static auto error_of(const std::expected<T, std::string>& got) -> std::string {
        return got.has_value() ? std::string{} : got.error();
    }

    auto emit(
        action what,
        std::string_view tool,
        std::string_view args,
        bool ok,
        std::string err,
        std::chrono::steady_clock::time_point start
    ) -> std::expected<void, std::string> {
        event ev{
            .what = what,
            .tool_name = std::string{tool},
            .arguments_json = std::string{args},
            .status = ok ? glove::mcp::tool_call_status::ok
                         : glove::mcp::tool_call_status::transport_error,
            .error_message = std::move(err),
            .at = std::chrono::system_clock::now(),
            .latency = std::chrono::steady_clock::now() - start,
        };
        return sink_->record(ev);
    }

    std::unique_ptr<glove::mcp::client> inner_;
    std::shared_ptr<sink> sink_;
};

} // namespace

auto make_audit_client(std::unique_ptr<glove::mcp::client> inner, std::shared_ptr<sink> s)
    -> std::unique_ptr<glove::mcp::client> {
    return std::make_unique<audit_client>(std::move(inner), std::move(s));
}

} // namespace glove::audit
