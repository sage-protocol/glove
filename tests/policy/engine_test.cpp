// Unit tests for the allow/deny-list policy engine.

#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <cstdio>
#include <memory>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto test_default_deny_blocks_unknown_tool() -> int {
    auto eng = glove::policy::make_allow_list_engine({});
    auto out = eng->check("anything", "{}");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    REQUIRE(out.reason.find("default deny") != std::string::npos);
    return 0;
}

auto test_allow_list_permits_named_tool() -> int {
    glove::policy::allow_list_options opts{
        .allow = {"echo", "grep"},
        .deny = {},
        .default_decision = glove::policy::decision::deny,
    };
    auto eng = glove::policy::make_allow_list_engine(std::move(opts));

    REQUIRE(eng->check("echo", "{}").verdict == glove::policy::decision::allow);
    REQUIRE(eng->check("grep", "{}").verdict == glove::policy::decision::allow);
    REQUIRE(eng->check("rm", "{}").verdict == glove::policy::decision::deny);
    return 0;
}

auto test_deny_takes_precedence_over_allow() -> int {
    glove::policy::allow_list_options opts{
        .allow = {"echo"},
        .deny = {"echo"},
        .default_decision = glove::policy::decision::allow,
    };
    auto eng = glove::policy::make_allow_list_engine(std::move(opts));
    auto out = eng->check("echo", "{}");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    REQUIRE(out.reason.find("deny list") != std::string::npos);
    return 0;
}

auto test_default_allow_with_deny_list() -> int {
    glove::policy::allow_list_options opts{
        .allow = {},
        .deny = {"dangerous"},
        .default_decision = glove::policy::decision::allow,
    };
    auto eng = glove::policy::make_allow_list_engine(std::move(opts));

    REQUIRE(eng->check("safe", "{}").verdict == glove::policy::decision::allow);
    REQUIRE(eng->check("dangerous", "{}").verdict == glove::policy::decision::deny);
    return 0;
}

} // namespace

auto main() -> int {
    if (test_default_deny_blocks_unknown_tool() != 0) {
        return 1;
    }
    if (test_allow_list_permits_named_tool() != 0) {
        return 1;
    }
    if (test_deny_takes_precedence_over_allow() != 0) {
        return 1;
    }
    if (test_default_allow_with_deny_list() != 0) {
        return 1;
    }
    return 0;
}
