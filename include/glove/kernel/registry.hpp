#pragma once

#include "glove/kernel/extension.hpp"
#include "glove/mcp/messages.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::kernel {

// Routes incoming tool calls to the right extension by namespace prefix.
// Tool names exposed to the agent are formed as `<extension>.<tool>` — the
// registry splits on the first `.` to dispatch.
class registry {
public:
    registry() = default;
    registry(const registry&) = delete;
    registry& operator=(const registry&) = delete;
    registry(registry&&) = delete;
    registry& operator=(registry&&) = delete;
    ~registry() = default;

    // Register an extension. Names must be unique across the registry; the
    // method returns an error if a duplicate is added.
    auto add(std::unique_ptr<extension> ext) -> std::expected<void, std::string>;

    // Aggregate `tools/list`: returns the union of every extension's tools
    // with the namespace prefix applied to each tool name.
    auto list_tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string>;

    // Dispatch a `tools/call`. `qualified_name` is the prefixed form
    // (`<extension>.<tool>`); the registry strips the prefix and forwards
    // the bare tool name to the matching extension.
    auto invoke(std::string_view qualified_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string>;

private:
    std::vector<std::unique_ptr<extension>> extensions_;
};

} // namespace glove::kernel
