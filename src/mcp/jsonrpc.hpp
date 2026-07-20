#pragma once

#include <glaze/glaze.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace glove::mcp {

// JSON-RPC 2.0 envelopes. Aggregate-reflected by glaze.
//
// Method-specific payloads (params / result) are carried as raw_json so
// the envelope layer is decoupled from MCP method semantics.

struct jsonrpc_request_envelope {
    std::string jsonrpc = "2.0";
    std::int64_t id = 0;
    std::string method;
    glz::raw_json params{"{}"};
};

struct jsonrpc_error_object {
    std::int64_t code = 0;
    std::string message;
};

struct jsonrpc_response_envelope {
    std::string jsonrpc;
    std::int64_t id = 0;
    std::optional<glz::raw_json> result;
    std::optional<jsonrpc_error_object> error;
};

// Server-side: a request as received from the agent. `id` is optional —
// notifications carry no id and expect no response.
struct jsonrpc_incoming_request {
    std::string jsonrpc;
    std::optional<std::int64_t> id;
    std::string method;
    std::optional<glz::raw_json> params;
};

} // namespace glove::mcp
