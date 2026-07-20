#pragma once

#include <glaze/glaze.hpp>

#include <optional>
#include <string>
#include <vector>

namespace glove::mcp {

// MCP method payloads. Field names match the spec exactly so glaze's
// aggregate reflection serializes them as the wire format requires.

struct mcp_client_info {
    std::string name;
    std::string version;
};

struct mcp_initialize_params {
    std::string protocolVersion;
    glz::raw_json capabilities{"{}"};
    mcp_client_info clientInfo;
};

struct mcp_server_info {
    std::string name;
    std::string version;
};

struct mcp_initialize_result {
    std::string protocolVersion;
    mcp_server_info serverInfo;
    glz::raw_json capabilities{"{}"};
};

struct mcp_tool_annotations {
    std::optional<bool> readOnlyHint;
    std::optional<bool> destructiveHint;
    std::optional<bool> idempotentHint;
    std::optional<bool> openWorldHint;
};

struct mcp_tool_def {
    std::string name;
    std::string description;
    glz::raw_json inputSchema{"{}"};
    std::optional<mcp_tool_annotations> annotations;
};

struct mcp_tools_list_result {
    std::vector<mcp_tool_def> tools;
};

struct mcp_tools_call_params {
    std::string name;
    glz::raw_json arguments{"{}"};
};

struct mcp_content_block {
    std::string type;
    std::string text;
};

struct mcp_tools_call_result {
    std::vector<mcp_content_block> content;
    bool isError = false;
    // 2025-06-18+: structured machine-readable result. Optional; servers that
    // predate this revision omit it entirely.
    std::optional<glz::raw_json> structuredContent;
};

struct mcp_resource_def {
    std::string uri;
    std::string name;
    std::optional<std::string> description;
    std::optional<std::string> mimeType;
};

struct mcp_resources_list_result {
    std::vector<mcp_resource_def> resources;
};

struct mcp_prompt_def {
    std::string name;
    std::optional<std::string> description;
    std::optional<glz::raw_json> arguments;
};

struct mcp_prompts_list_result {
    std::vector<mcp_prompt_def> prompts;
};

} // namespace glove::mcp
