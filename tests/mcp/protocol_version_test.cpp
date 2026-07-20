// Protocol-version regression: drives parse_initialize_result with crafted
// envelopes for each supported MCP version, plus one unknown version that
// must be rejected.

#include "src/mcp/codec.hpp"

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto initialize_response(std::string_view version) -> std::string {
    std::string s;
    s.append(R"({"jsonrpc":"2.0","id":1,"result":{)");
    s.append(R"("protocolVersion":")");
    s.append(version);
    s.append(R"(",)");
    s.append(R"("serverInfo":{"name":"f","version":"0"},)");
    s.append(R"("capabilities":{}}})");
    return s;
}

auto check_accept(std::string_view version) -> int {
    auto frame = initialize_response(version);
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto info = glove::mcp::codec::parse_initialize_result(*env);
    if (!info.has_value()) {
        std::fprintf(
            stderr,
            "rejected supported version '%s': %s\n",
            std::string{version}.c_str(),
            info.error().c_str()
        );
        return 1;
    }
    REQUIRE(info->protocol_version == version);
    return 0;
}

auto run() -> int {
    for (auto v : glove::mcp::codec::supported_protocol_versions) {
        if (check_accept(v) != 0) {
            return 1;
        }
    }

    // Unknown version must be rejected.
    auto frame = initialize_response("1999-01-01");
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto info = glove::mcp::codec::parse_initialize_result(*env);
    REQUIRE(!info.has_value());
    REQUIRE(info.error().find("unsupported protocolVersion") != std::string::npos);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
