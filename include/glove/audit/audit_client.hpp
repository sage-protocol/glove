#pragma once

#include "glove/audit/sink.hpp"
#include "glove/mcp/client.hpp"

#include <memory>

namespace glove::audit {

// Wrap an mcp::client and emit one audit event per call (initialize,
// list_tools, call_tool) after the inner call returns. Pass-through for
// results; the sink only observes.
auto make_audit_client(std::unique_ptr<glove::mcp::client> inner, std::shared_ptr<sink> sink)
    -> std::unique_ptr<glove::mcp::client>;

} // namespace glove::audit
