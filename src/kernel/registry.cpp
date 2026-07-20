#include "glove/kernel/registry.hpp"

#include "glove/kernel/extension.hpp"
#include "glove/mcp/messages.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::kernel {

auto registry::add(std::unique_ptr<extension> ext) -> std::expected<void, std::string> {
    if (!ext) {
        return std::unexpected(std::string{"registry::add: null extension"});
    }
    auto incoming_name = ext->name();
    for (const auto& existing : extensions_) {
        if (existing->name() == incoming_name) {
            return std::unexpected(
                std::string{"registry::add: duplicate extension name '"} +
                std::string{incoming_name} + "'"
            );
        }
    }
    extensions_.push_back(std::move(ext));
    return {};
}

auto registry::list_tools()
    -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> {
    std::vector<glove::mcp::tool_descriptor> out;
    for (const auto& ext : extensions_) {
        auto sub = ext->tools();
        if (!sub) {
            return std::unexpected(
                std::string{"extension '"} + std::string{ext->name()} + "': " + sub.error()
            );
        }
        const std::string prefix = std::string{ext->name()} + ".";
        for (auto& t : *sub) {
            t.name = prefix + t.name;
            out.push_back(std::move(t));
        }
    }
    return out;
}

auto registry::invoke(std::string_view qualified_name, std::string_view arguments_json)
    -> std::expected<glove::mcp::tool_call_result, std::string> {
    const auto dot = qualified_name.find('.');
    if (dot == std::string_view::npos) {
        return std::unexpected(
            std::string{"tool name missing namespace prefix: '"} + std::string{qualified_name} + "'"
        );
    }
    const std::string_view ext_name = qualified_name.substr(0, dot);
    const std::string_view bare_name = qualified_name.substr(dot + 1);

    for (const auto& ext : extensions_) {
        if (ext->name() == ext_name) {
            return ext->invoke(bare_name, arguments_json);
        }
    }
    return std::unexpected(std::string{"no extension named '"} + std::string{ext_name} + "'");
}

} // namespace glove::kernel
