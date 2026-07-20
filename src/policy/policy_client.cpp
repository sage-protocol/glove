#include "glove/policy/policy_client.hpp"

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::policy {

namespace {

class policy_client final : public glove::mcp::client {
public:
    policy_client(std::unique_ptr<glove::mcp::client> inner, std::shared_ptr<engine> policy)
        : inner_{std::move(inner)}, policy_{std::move(policy)} {}

    auto initialize(std::string_view client_name, std::string_view client_version)
        -> std::expected<glove::mcp::server_info, std::string> override {
        return inner_->initialize(client_name, client_version);
    }

    auto list_tools()
        -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        auto tools = inner_->list_tools();
        if (!tools) {
            return tools;
        }
        std::vector<glove::mcp::tool_descriptor> permitted;
        permitted.reserve(tools->size());
        for (auto& t : *tools) {
            if (policy_->visible(t.name)) {
                permitted.push_back(std::move(t));
            }
        }
        return permitted;
    }

    auto call_tool(const glove::mcp::tool_call_request& req)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        auto out = policy_->check(req.name, req.arguments_json);
        if (out.verdict == decision::deny) {
            return glove::mcp::tool_call_result{
                .status = glove::mcp::tool_call_status::invalid_arguments,
                .content = {},
                .structured_json = {},
                .error_message = std::string{"policy denied: "} + std::move(out.reason),
            };
        }
        return inner_->call_tool(req);
    }

private:
    std::unique_ptr<glove::mcp::client> inner_;
    std::shared_ptr<engine> policy_;
};

} // namespace

auto make_policy_client(std::unique_ptr<glove::mcp::client> inner, std::shared_ptr<engine> policy)
    -> std::unique_ptr<glove::mcp::client> {
    return std::make_unique<policy_client>(std::move(inner), std::move(policy));
}

} // namespace glove::policy
