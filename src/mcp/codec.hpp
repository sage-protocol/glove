#pragma once

#include "glove/mcp/messages.hpp"

#include "src/mcp/jsonrpc.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace glove::mcp::codec {

// Protocol version we advertise in initialize requests. Servers may respond
// with an older version; we accept the negotiated value rather than
// rejecting. Bump in one place when MCP rolls forward.
inline constexpr std::string_view client_protocol_version = "2025-06-18";

// Versions we accept from a server's initialize response. Tested explicitly
// against yams (2024-11-05) and against fakes for the newer revisions.
inline constexpr std::string_view supported_protocol_versions[] = {
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
};

// Build a single-line JSON-RPC 2.0 frame for the named method, with `params`
// supplied as already-serialized JSON. Caller is responsible for ensuring
// `params_json` is a valid JSON object/array literal (or "{}" for none).
auto encode_request(std::int64_t id, std::string_view method, std::string_view params_json)
    -> std::expected<std::string, std::string>;

auto decode_response(std::string_view frame)
    -> std::expected<jsonrpc_response_envelope, std::string>;

// MCP method-specific helpers. Each returns either the framed request as a
// single line of JSON, or a typed result projected into the public types.

auto build_initialize_request(
    std::int64_t id, std::string_view client_name, std::string_view client_version
) -> std::expected<std::string, std::string>;

auto parse_initialize_result(const jsonrpc_response_envelope& env)
    -> std::expected<server_info, std::string>;

// Build the `notifications/initialized` notification frame. Returned frame is
// a single line and contains no `id` field; transports should send it without
// expecting a response.
auto build_initialized_notification() -> std::expected<std::string, std::string>;

auto build_tools_list_request(std::int64_t id) -> std::expected<std::string, std::string>;

auto parse_tools_list_result(const jsonrpc_response_envelope& env)
    -> std::expected<std::vector<tool_descriptor>, std::string>;

auto build_tools_call_request(std::int64_t id, const tool_call_request& req)
    -> std::expected<std::string, std::string>;

auto parse_tools_call_result(const jsonrpc_response_envelope& env)
    -> std::expected<tool_call_result, std::string>;

auto build_resources_list_request(std::int64_t id) -> std::expected<std::string, std::string>;

auto parse_resources_list_result(const jsonrpc_response_envelope& env)
    -> std::expected<std::vector<resource_descriptor>, std::string>;

auto build_prompts_list_request(std::int64_t id) -> std::expected<std::string, std::string>;

auto parse_prompts_list_result(const jsonrpc_response_envelope& env)
    -> std::expected<std::vector<prompt_descriptor>, std::string>;

// --- Server-side helpers (read from agent, write back to agent) -----------

auto decode_request(std::string_view frame) -> std::expected<jsonrpc_incoming_request, std::string>;

// Build a response frame carrying a pre-serialized result JSON object.
// Caller passes the id from the request being answered.
auto encode_response_with_result(std::int64_t id, std::string_view result_json)
    -> std::expected<std::string, std::string>;

// Build a JSON-RPC error response. Standard codes: -32700 parse error,
// -32600 invalid request, -32601 method not found, -32602 invalid params,
// -32603 internal error. Custom codes are caller-defined.
auto encode_response_with_error(std::int64_t id, std::int64_t code, std::string_view message)
    -> std::expected<std::string, std::string>;

} // namespace glove::mcp::codec
