#pragma once

#include "glove/mcp/messages.hpp"

#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace glove::kernel {

// One unit of capability the contained agent can call. Concrete extensions
// include `mcp_extension` (forwards to an upstream MCP server), `fs_extension`
// (sandboxed filesystem), `net_extension` (controlled HTTP egress), and so
// on — each authored as a plain class today and as a P2996-reflected struct
// once the compiler ships.
//
// Threading: registries may invoke an extension from multiple kernel threads
// concurrently if the agent pipelines requests; implementations must serialise
// mutable state internally.
class extension {
public:
    extension() = default;
    extension(const extension&) = delete;
    extension& operator=(const extension&) = delete;
    extension(extension&&) = delete;
    extension& operator=(extension&&) = delete;
    virtual ~extension() = default;

    // Stable identifier. Used as a namespace prefix on every tool name this
    // extension exposes (so two extensions can both define `read` without
    // collision).
    virtual auto name() const -> std::string_view = 0;

    // Tools the extension exposes right now. Called once per agent
    // `tools/list` request; if the underlying source changes, the next call
    // reflects it. Implementations are expected to cache where appropriate.
    virtual auto tools()
        -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> = 0;

    // Dispatch a tool call. `tool_name` here is the *unprefixed* name —
    // the registry strips the `<extension>.` prefix before forwarding.
    virtual auto invoke(std::string_view tool_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string> = 0;
};

} // namespace glove::kernel
