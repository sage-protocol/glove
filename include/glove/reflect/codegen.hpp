#pragma once

// Reflection-driven codec sketch.
//
// This header is the design target for phase 1 of the project plan: replacing
// the hand-written codec types in `src/mcp/{jsonrpc,mcp_messages}.hpp` and
// the manual JSON-Schema synthesis with one that walks members of an
// annotated struct via C++26 P2996 reflection.
//
// Today, mainline clang and Apple clang do not ship P2996. The gating option
// is OFF by default; flip GLOVE_REFLECTION=ON only when building under a
// P2996-capable compiler (e.g. the Bloomberg clang-p2996 fork). The
// implementation below is intentionally compiled out — it documents intent in
// a single place that future work will fill in.
//
// Why this lives in a header that compiles to nothing: the design value is in
// freezing the *boundary* — what user code looks like, what the registry
// emits — so the rest of the project (policy, audit, transport) can be built
// against the eventual surface. When the compiler arrives, dropping this
// header in flips the project from manual codec to reflection-driven, and
// every other layer keeps working unchanged.

#if defined(GLOVE_HAS_REFLECTION)

#    include <glove/mcp/messages.hpp>

#    include <experimental/meta>
#    include <string>
#    include <string_view>

namespace glove::reflect {

// Author-side annotation. Tool authors decorate fields and the struct itself
// to drive codegen. The annotation values are consteval-readable via
// `annotations_of`.
struct tool_meta {
    std::string_view name;
    std::string_view description;
};

struct param_meta {
    std::string_view label;
    std::string_view description;
    bool required = true;
};

// Synthesize a JSON-Schema object describing the input shape of a tool struct
// `T`. Walks members_of(^^T) at consteval, reads each member's `param_meta`
// annotation, and recursively maps C++ types to JSON-Schema types.
//
// Sketch only; the body cannot be written until P2996 lands. The intended
// shape:
//
//     template <class T>
//     consteval auto input_schema_of() -> std::string {
//         std::string out = R"({"type":"object","properties":{)";
//         template for (constexpr auto m : nonstatic_data_members_of(^^T)) {
//             constexpr auto p = annotations_of<param_meta>(m);
//             out += '"';
//             out += identifier_of(m);
//             out += R"(":)";
//             out += json_schema_of_type<typename_of(m)>();
//             ...
//         }
//         out += "}}";
//         return out;
//     }
//
// Likewise, `marshal_request_of<T>(T const&)` and `unmarshal_request_of<T>`
// would walk members and call glaze (or a P2996-driven equivalent) per
// field, eliminating the hand-written `mcp_messages.hpp` shapes.

template<class T> consteval auto input_schema_of() -> std::string; // intentionally undefined

template<class T>
consteval auto descriptor_of() -> glove::mcp::tool_descriptor; // intentionally undefined

} // namespace glove::reflect

#else

namespace glove::reflect {

// When GLOVE_REFLECTION is off, the registry is unavailable. Including this
// header on a non-reflection build is allowed (so consumers don't need to
// scatter their own #ifdefs), but no callable surface is exposed.
inline constexpr bool reflection_available = false;

} // namespace glove::reflect

#endif // GLOVE_HAS_REFLECTION
