#pragma once

#include "glove/policy/decision.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::policy {

// Stateless decision engine. Implementations are queried before each tool
// invocation and may consult the tool name and serialized arguments.
//
// Engines must be safe for concurrent calls — wrapping clients may be shared
// across agent threads.
class engine {
public:
    engine() = default;
    engine(const engine&) = delete;
    engine& operator=(const engine&) = delete;
    engine(engine&&) = delete;
    engine& operator=(engine&&) = delete;
    virtual ~engine() = default;

    virtual auto check(std::string_view tool_name, std::string_view arguments_json) const
        -> outcome = 0;

    // Name-only visibility used by tools/list. Argument constraints tighten
    // calls but do not hide an otherwise permitted tool.
    virtual auto visible(std::string_view tool_name) const -> bool = 0;
};

struct allow_list_options {
    // Tools whose names appear here are permitted (subject to deny_list).
    std::vector<std::string> allow;
    // Tools whose names appear here are always denied; takes precedence over
    // allow.
    std::vector<std::string> deny;
    // What to return when a tool name appears in neither list.
    decision default_decision = decision::deny;
};

// Build an allow/deny-list engine. Empty allow_list combined with
// default_decision = deny effectively denies all tools.
auto make_allow_list_engine(allow_list_options opts) -> std::unique_ptr<engine>;

// One argument-level constraint. The agent's `tools/call` is permitted only
// when the JSON value at `field` (a top-level argument key) is a string whose
// value starts with `required_prefix`. Absolute prefixes use canonical path
// containment instead of byte-prefix matching, preventing `..`, symlink, and
// sibling-prefix escapes. Multiple rules may apply; all must pass.
struct argument_prefix_rule {
    std::string tool_name;       // qualified, e.g. "fs.read_file"
    std::string field;           // top-level argument field, e.g. "path"
    std::string required_prefix; // value must start with this
};

struct jsonpath_options {
    // Tools allowed by name. An entry here without any prefix rules permits
    // any arguments. With prefix rules, all rules must pass.
    std::vector<std::string> allow;
    // Tools denied by name; takes precedence over everything else.
    std::vector<std::string> deny;
    // Argument-level constraints. A rule's tool must also appear in
    // `allow` for the tool to be reachable; rules tighten what arguments
    // the allowed tool will accept.
    std::vector<argument_prefix_rule> prefix_rules;
    decision default_decision = decision::deny;
};

// Build an engine that combines name-based allow/deny with argument-level
// prefix constraints. Parses `arguments_json` with glaze; non-object args
// or missing/wrong-type fields fail closed.
auto make_jsonpath_engine(jsonpath_options opts) -> std::unique_ptr<engine>;

} // namespace glove::policy
