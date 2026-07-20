#pragma once

#include "glove/kernel/extension.hpp"
#include "glove/mcp/client.hpp"

#include <memory>
#include <string>

namespace glove::kernel {

// Extension that exposes one upstream MCP server's tools to the agent.
// Construction takes ownership of an `mcp::client`; the extension's `name()`
// is what the registry uses as the tool-name prefix the agent sees.
//
// The client is initialized once on first use (lazy_init wrapping is the
// caller's responsibility — typically via `mcp::make_lazy_init_client`).
auto make_mcp_extension(std::string name, std::unique_ptr<glove::mcp::client> upstream)
    -> std::unique_ptr<extension>;

} // namespace glove::kernel
