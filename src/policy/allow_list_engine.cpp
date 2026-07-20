#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::policy {

namespace {

class allow_list_engine final : public engine {
public:
    explicit allow_list_engine(allow_list_options opts) : opts_{std::move(opts)} {}

    auto check(std::string_view tool_name, std::string_view /*arguments_json*/) const
        -> outcome override {
        if (contains(opts_.deny, tool_name)) {
            return outcome{
                .verdict = decision::deny,
                .reason = std::string{"tool '"} + std::string{tool_name} + "' is in deny list",
            };
        }
        if (contains(opts_.allow, tool_name)) {
            return outcome{
                .verdict = decision::allow,
                .reason = std::string{"tool '"} + std::string{tool_name} + "' is in allow list",
            };
        }
        if (opts_.default_decision == decision::allow) {
            return outcome{
                .verdict = decision::allow,
                .reason = std::string{"default allow"},
            };
        }
        return outcome{
            .verdict = decision::deny,
            .reason = std::string{"tool '"} + std::string{tool_name} +
                      "' not in allow list (default deny)",
        };
    }

    auto visible(std::string_view tool_name) const -> bool override {
        return !contains(opts_.deny, tool_name) &&
               (contains(opts_.allow, tool_name) || opts_.default_decision == decision::allow);
    }

private:
    static auto contains(const std::vector<std::string>& list, std::string_view name) -> bool {
        return std::any_of(list.begin(), list.end(), [name](const std::string& s) {
            return s == name;
        });
    }

    allow_list_options opts_;
};

} // namespace

auto make_allow_list_engine(allow_list_options opts) -> std::unique_ptr<engine> {
    return std::make_unique<allow_list_engine>(std::move(opts));
}

} // namespace glove::policy
