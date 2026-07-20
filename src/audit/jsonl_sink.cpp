#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"

#include <glaze/glaze.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace glove::audit {

// Wire-shape struct: glaze serializes this aggregate into one JSON object per
// event. Field names are deliberately stable so downstream tooling (e.g. log
// shippers) doesn't break on internal renames. At namespace scope (not
// anonymous) so glaze's reflection can take its address.
struct wire_event {
    std::string action;
    std::string tool;
    std::string arguments;
    std::string status;
    std::string error;
    std::int64_t timestamp_ns;
    std::int64_t latency_ns;
};

namespace {

auto status_name(glove::mcp::tool_call_status s) -> std::string_view {
    using glove::mcp::tool_call_status;
    switch (s) {
    case tool_call_status::ok:
        return "ok";
    case tool_call_status::tool_not_found:
        return "tool_not_found";
    case tool_call_status::invalid_arguments:
        return "invalid_arguments";
    case tool_call_status::execution_error:
        return "execution_error";
    case tool_call_status::transport_error:
        return "transport_error";
    }
    return "unknown";
}

auto action_name(action a) -> std::string_view {
    switch (a) {
    case action::list_tools:
        return "list_tools";
    case action::call_tool:
        return "call_tool";
    case action::initialize:
        return "initialize";
    case action::agent_launch:
        return "agent_launch";
    case action::agent_exit:
        return "agent_exit";
    case action::egress:
        return "egress";
    }
    return "unknown";
}

class jsonl_sink final : public sink {
public:
    explicit jsonl_sink(std::ofstream stream) : stream_{std::move(stream)} {}

    auto record(const event& e) -> std::expected<void, std::string> override {
        wire_event w{
            .action = std::string{action_name(e.what)},
            .tool = e.tool_name,
            .arguments = e.arguments_json,
            .status = std::string{status_name(e.status)},
            .error = e.error_message,
            .timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(e.at.time_since_epoch())
                    .count(),
            .latency_ns = e.latency.count(),
        };
        auto encoded = glz::write_json(w);
        if (!encoded) {
            return std::unexpected(
                std::string{"glaze write_json: "} +
                glz::format_error(encoded.error(), std::string{})
            );
        }

        std::scoped_lock lock{mu_};
        stream_ << *encoded << '\n';
        if (!stream_) {
            return std::unexpected(std::string{"jsonl_sink: write failed"});
        }
        stream_.flush();
        return {};
    }

private:
    std::mutex mu_;
    std::ofstream stream_;
};

} // namespace

auto make_jsonl_sink(const std::filesystem::path& path)
    -> std::expected<std::shared_ptr<sink>, std::string> {
    std::ofstream stream{path, std::ios::out | std::ios::app | std::ios::binary};
    if (!stream) {
        return std::unexpected(std::string{"jsonl_sink: cannot open "} + path.string());
    }
    return std::make_shared<jsonl_sink>(std::move(stream));
}

} // namespace glove::audit
