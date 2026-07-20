#pragma once

#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

struct change_apply_trust_key {
    std::string key_id;
    std::string algorithm;
    std::string public_key_base64url;
    std::uint64_t not_before_ms = 0;
    std::uint64_t not_after_ms = 0;

    auto operator==(const change_apply_trust_key&) const -> bool = default;
};

// Root-controlled verification policy. load() requires an owner-only,
// no-follow, single-link regular file owned by the effective Glove account.
// In production gloved runs as root; non-root loading exists for tests and
// unprivileged development only.
class change_apply_trust_policy final {
public:
    [[nodiscard]] static auto load(const std::filesystem::path& path)
        -> result<change_apply_trust_policy>;

    [[nodiscard]] auto revision() const noexcept -> std::uint64_t { return revision_; }

    [[nodiscard]] auto keys() const noexcept -> const std::vector<change_apply_trust_key>& {
        return keys_;
    }

    [[nodiscard]] auto active_key(std::string_view key_id, std::uint64_t now_ms) const
        -> result<const change_apply_trust_key*>;

    [[nodiscard]] auto authorization_key(
        std::string_view key_id,
        std::uint64_t issued_at_ms,
        std::uint64_t expires_at_ms,
        std::uint64_t now_ms
    ) const -> result<const change_apply_trust_key*>;

private:
    change_apply_trust_policy(std::uint64_t revision, std::vector<change_apply_trust_key> keys);

    std::uint64_t revision_ = 0;
    std::vector<change_apply_trust_key> keys_;
};

} // namespace glove::supervisor
