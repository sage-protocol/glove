#pragma once

#include "glove/mcp/client.hpp"

#include <memory>
#include <string>

namespace glove::mcp {

// Wrap a client so initialize() runs at most once. The wrapper:
//   - on the first list_tools / call_tool, runs initialize(client_name,
//     client_version) before delegating
//   - on an explicit initialize() call, runs the handshake (and remembers the
//     result so subsequent auto-init is suppressed)
//   - returns a cached server_info from any later initialize() call
//
// Thread-safe: the gate is guarded by a mutex; concurrent first calls block
// until initialization completes once.
auto make_lazy_init_client(
    std::unique_ptr<client> inner, std::string client_name, std::string client_version
) -> std::unique_ptr<client>;

} // namespace glove::mcp
