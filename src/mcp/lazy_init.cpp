#include "glove/mcp/lazy_init.hpp"

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"

#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::mcp {

namespace {

class lazy_init_client final : public client {
public:
    lazy_init_client(std::unique_ptr<client> inner, std::string name, std::string version)
        : inner_{std::move(inner)}, name_{std::move(name)}, version_{std::move(version)} {}

    auto initialize(std::string_view client_name, std::string_view client_version)
        -> std::expected<server_info, std::string> override {
        std::scoped_lock lock{mu_};
        if (cached_info_) {
            return *cached_info_;
        }
        // Caller-supplied name/version override the construction-time defaults
        // when explicit. Empty means "use stored defaults".
        std::string n = client_name.empty() ? name_ : std::string{client_name};
        std::string v = client_version.empty() ? version_ : std::string{client_version};
        auto info = inner_->initialize(n, v);
        if (info) {
            cached_info_ = *info;
        }
        return info;
    }

    auto list_tools() -> std::expected<std::vector<tool_descriptor>, std::string> override {
        if (auto err = ensure_initialized(); !err) {
            return std::unexpected(err.error());
        }
        return inner_->list_tools();
    }

    auto call_tool(const tool_call_request& req)
        -> std::expected<tool_call_result, std::string> override {
        if (auto err = ensure_initialized(); !err) {
            return std::unexpected(err.error());
        }
        return inner_->call_tool(req);
    }

private:
    auto ensure_initialized() -> std::expected<void, std::string> {
        std::scoped_lock lock{mu_};
        if (cached_info_) {
            return {};
        }
        auto info = inner_->initialize(name_, version_);
        if (!info) {
            return std::unexpected(info.error());
        }
        cached_info_ = *info;
        return {};
    }

    std::unique_ptr<client> inner_;
    std::string name_;
    std::string version_;
    std::mutex mu_;
    std::optional<server_info> cached_info_;
};

} // namespace

auto make_lazy_init_client(
    std::unique_ptr<client> inner, std::string client_name, std::string client_version
) -> std::unique_ptr<client> {
    return std::make_unique<lazy_init_client>(
        std::move(inner), std::move(client_name), std::move(client_version)
    );
}

} // namespace glove::mcp
