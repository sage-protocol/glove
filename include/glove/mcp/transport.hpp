#pragma once

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace glove::mcp {

// Frame-level wire transport. Concrete impls plug into different sandbox
// extension shapes:
//   - stdio_transport: each upstream MCP server runs as a child process, giving
//     us OS-level isolation per server with a uniform interface.
//   - in_memory_transport: a synchronous fake for tests.
//
// Frames are opaque to the transport; the codec layer (forthcoming) turns them
// into typed messages.
class transport {
public:
    transport() = default;
    transport(const transport&) = delete;
    transport& operator=(const transport&) = delete;
    transport(transport&&) = delete;
    transport& operator=(transport&&) = delete;
    virtual ~transport() = default;

    virtual auto send(std::string_view frame) -> std::expected<void, std::string> = 0;
    virtual auto recv() -> std::expected<std::string, std::string> = 0;
};

// Build an in-memory transport whose responses come from `handler(frame)`.
// Useful for testing the client surface without a real server. Returning
// std::nullopt models a notification: the handler runs but no frame is queued
// for the next recv() — matching how stdio MCP servers handle notifications
// (no wire response).
auto make_in_memory_transport(std::function<std::optional<std::string>(std::string_view)> handler)
    -> std::unique_ptr<transport>;

} // namespace glove::mcp
