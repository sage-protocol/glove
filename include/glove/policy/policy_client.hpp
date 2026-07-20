#pragma once

#include "glove/mcp/client.hpp"
#include "glove/policy/engine.hpp"

#include <memory>

namespace glove::policy {

// Wrap an mcp::client with a policy. The returned client:
//   - passes initialize() through unchanged
//   - filters list_tools() to only those the policy allows
//   - on call_tool(), runs check() first; on deny, returns a tool_call_result
//     with status = invalid_arguments and the policy's reason as the
//     error_message — without ever calling the underlying transport.
//
// The decorator owns the inner client and shares the engine (the engine is
// expected to be threadsafe and may be shared across multiple clients).
auto make_policy_client(std::unique_ptr<glove::mcp::client> inner, std::shared_ptr<engine> policy)
    -> std::unique_ptr<glove::mcp::client>;

} // namespace glove::policy
