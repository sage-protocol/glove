#pragma once

#include <cstdint>
#include <string>

namespace glove::mcp {

// MCP advisory hints attached to a tool. Servers populate any subset; absent
// hints are treated as "unknown", which is safer-than-permissive in policy
// decisions.
struct tool_annotations {
    bool read_only_hint = false;
    bool destructive_hint = false;
    bool idempotent_hint = false;
    bool open_world_hint = false;
    bool has_annotations = false; // false if server omitted the block entirely
};

// One tool the upstream MCP server advertises.
//
// `input_schema_json` is opaque JSON for now. When the codec layer lands it
// becomes a parsed schema; the rest of the surface stays the same.
struct tool_descriptor {
    std::string name;
    std::string description;
    std::string input_schema_json;
    tool_annotations annotations;
};

struct tool_call_request {
    std::string name;
    std::string arguments_json;
};

enum class tool_call_status : std::uint8_t {
    ok,
    tool_not_found,
    invalid_arguments,
    execution_error,
    transport_error,
};

struct tool_call_result {
    tool_call_status status = tool_call_status::ok;
    // Concatenated text from `content[]` (one block per server-emitted entry,
    // joined by `\n`). Always populated when status == ok.
    std::string content;
    // Verbatim JSON from the 2025-06-18+ `structuredContent` field, when the
    // server populated it. Empty otherwise. Callers that want machine-readable
    // results should prefer this; `content` is the human-readable summary.
    std::string structured_json;
    std::string error_message;
};

// Result of the MCP `initialize` handshake.
struct server_info {
    std::string name;
    std::string version;
    std::string protocol_version;
};

// MCP `resources/list` entry. URIs are server-defined (e.g. `file://`,
// `git://`, `https://`); description and mime_type are optional.
struct resource_descriptor {
    std::string uri;
    std::string name;
    std::string description;
    std::string mime_type;
};

// MCP `prompts/list` entry. Prompts are templated text; arguments_json is
// the verbatim JSON-Schema array describing accepted arguments, or empty if
// the prompt takes none.
struct prompt_descriptor {
    std::string name;
    std::string description;
    std::string arguments_json;
};

} // namespace glove::mcp
