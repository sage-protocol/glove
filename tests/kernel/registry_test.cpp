// Routes tool calls to extensions by namespace prefix; rejects unknowns.

#include "glove/kernel/extension.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/mcp/messages.hpp"

#include <cstdio>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class fake_extension final : public glove::kernel::extension {
public:
    fake_extension(std::string name, std::string tool_name)
        : name_{std::move(name)}, tool_name_{std::move(tool_name)} {}

    auto name() const -> std::string_view override { return name_; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return std::vector<glove::mcp::tool_descriptor>{
            {.name = tool_name_,
             .description = "fake",
             .input_schema_json = "{}",
             .annotations = {}}
        };
    }

    auto invoke(std::string_view tool_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        last_tool_ = std::string{tool_name};
        last_args_ = std::string{arguments_json};
        return glove::mcp::tool_call_result{
            .status = glove::mcp::tool_call_status::ok,
            .content = std::string{"ran "} + last_tool_,
            .structured_json = "",
            .error_message = "",
        };
    }

    std::string last_tool_;
    std::string last_args_;

private:
    std::string name_;
    std::string tool_name_;
};

auto run() -> int {
    glove::kernel::registry reg;
    auto ext_a = std::make_unique<fake_extension>("alpha", "ping");
    auto ext_b = std::make_unique<fake_extension>("beta", "pong");
    auto* a_raw = ext_a.get();
    auto* b_raw = ext_b.get();
    REQUIRE(reg.add(std::move(ext_a)).has_value());
    REQUIRE(reg.add(std::move(ext_b)).has_value());

    // Duplicate name is rejected.
    auto dup = std::make_unique<fake_extension>("alpha", "x");
    REQUIRE(!reg.add(std::move(dup)).has_value());

    // Aggregated list applies the prefix.
    auto tools = reg.list_tools();
    REQUIRE(tools.has_value());
    REQUIRE(tools->size() == 2);
    REQUIRE((*tools)[0].name == "alpha.ping");
    REQUIRE((*tools)[1].name == "beta.pong");

    // Routing splits on the first dot.
    auto out = reg.invoke("alpha.ping", R"({"x":1})");
    REQUIRE(out.has_value());
    REQUIRE(out->status == glove::mcp::tool_call_status::ok);
    REQUIRE(out->content == "ran ping");
    REQUIRE(a_raw->last_tool_ == "ping");
    REQUIRE(a_raw->last_args_.find("\"x\":1") != std::string::npos);
    REQUIRE(b_raw->last_tool_.empty());

    // Missing prefix or missing extension surface as errors.
    REQUIRE(!reg.invoke("noprefix", "{}").has_value());
    REQUIRE(!reg.invoke("gamma.foo", "{}").has_value());

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
