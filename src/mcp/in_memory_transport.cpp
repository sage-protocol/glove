#include "glove/mcp/transport.hpp"

#include <condition_variable>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace glove::mcp {

namespace {

// Synchronous request/response transport: every send invokes `handler_` once.
// If the handler returns a value, it is queued for the next recv(). If it
// returns std::nullopt, nothing is queued — modelling MCP notifications.
class in_memory_transport final : public transport {
public:
    explicit in_memory_transport(
        std::function<std::optional<std::string>(std::string_view)> handler
    )
        : handler_{std::move(handler)} {}

    auto send(std::string_view frame) -> std::expected<void, std::string> override {
        std::optional<std::string> response = handler_(frame);
        if (!response) {
            return {};
        }
        {
            std::scoped_lock lock{mu_};
            pending_.emplace(std::move(*response));
        }
        cv_.notify_one();
        return {};
    }

    auto recv() -> std::expected<std::string, std::string> override {
        std::unique_lock lock{mu_};
        cv_.wait(lock, [this] { return pending_.has_value(); });
        std::string out = std::move(*pending_);
        pending_.reset();
        return out;
    }

private:
    std::function<std::optional<std::string>(std::string_view)> handler_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::optional<std::string> pending_;
};

} // namespace

auto make_in_memory_transport(std::function<std::optional<std::string>(std::string_view)> handler)
    -> std::unique_ptr<transport> {
    return std::make_unique<in_memory_transport>(std::move(handler));
}

} // namespace glove::mcp
