#include "glove/kernel/mcp_extension.hpp"

#include "glove/kernel/extension.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::kernel {

namespace {

class mcp_extension_impl final : public extension {
public:
    mcp_extension_impl(std::string name, std::unique_ptr<glove::mcp::client> upstream)
        : name_{std::move(name)}, upstream_{std::move(upstream)} {}

    auto name() const -> std::string_view override { return name_; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return upstream_->list_tools();
    }

    auto invoke(std::string_view tool_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        glove::mcp::tool_call_request req{
            .name = std::string{tool_name},
            .arguments_json = std::string{arguments_json},
        };
        return upstream_->call_tool(req);
    }

private:
    std::string name_;
    std::unique_ptr<glove::mcp::client> upstream_;
};

} // namespace

auto make_mcp_extension(std::string name, std::unique_ptr<glove::mcp::client> upstream)
    -> std::unique_ptr<extension> {
    return std::make_unique<mcp_extension_impl>(std::move(name), std::move(upstream));
}

} // namespace glove::kernel
