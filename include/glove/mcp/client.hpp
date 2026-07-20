#pragma once

#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::mcp {

// High-level client over a transport. One client per upstream MCP server.
//
// The shape is fixed; the wire codec is not yet wired in. Once a JSON codec
// (or a reflection-driven codec, see GLOVE_REFLECTION) is in place, both
// methods will round-trip to the upstream server. Until then, the default
// implementation returns `transport_error` so calls fail loudly rather than
// silently.
class client {
public:
    client() = default;
    client(const client&) = delete;
    client& operator=(const client&) = delete;
    client(client&&) = delete;
    client& operator=(client&&) = delete;
    virtual ~client() = default;

    // Run the MCP `initialize` handshake and `notifications/initialized`
    // follow-up. Must be called before list_tools / call_tool against any
    // server that requires the handshake (which is most of them).
    virtual auto initialize(std::string_view client_name, std::string_view client_version)
        -> std::expected<server_info, std::string> = 0;

    virtual auto list_tools() -> std::expected<std::vector<tool_descriptor>, std::string> = 0;

    virtual auto call_tool(const tool_call_request& req)
        -> std::expected<tool_call_result, std::string> = 0;
};

// Build a client over the given transport. Today this returns a stub that
// reports "codec not yet wired" on every call but exercises the transport
// boundary so the plumbing is sanitizer-tested.
auto make_client(std::unique_ptr<transport> t) -> std::unique_ptr<client>;

} // namespace glove::mcp
