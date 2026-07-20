#pragma once

#include "glove/supervisor/path_exposure.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace glove::supervisor {

inline constexpr std::uint64_t default_path_exposure_journal_bytes =
    std::uint64_t{8} * 1024U * 1024U;

struct path_exposure_create_record {
    path_exposure_descriptor descriptor;
    std::string request_id;
    std::string request_digest;
    std::string host_path;
    std::string parent_identity_digest;

    auto operator==(const path_exposure_create_record&) const -> bool = default;
};

struct path_exposure_revoke_record {
    std::string request_id;
    std::string request_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    path_exposure_state state = path_exposure_state::revoked;
    std::uint64_t revoked_at_ms = 0;

    auto operator==(const path_exposure_revoke_record&) const -> bool = default;
};

using path_exposure_journal_record =
    std::variant<path_exposure_create_record, path_exposure_revoke_record>;

// Bounded, exclusive, owner-only persistence for dynamic exposure authority.
// Business validation remains in path_exposure_registry; this class owns exact
// append, sync, hash-chain verification, and replay ordering.
class path_exposure_journal final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class path_exposure_journal;
    };

    path_exposure_journal(construction_token token, std::unique_ptr<implementation> state);
    path_exposure_journal(const path_exposure_journal&) = delete;
    auto operator=(const path_exposure_journal&) -> path_exposure_journal& = delete;
    path_exposure_journal(path_exposure_journal&&) noexcept;
    auto operator=(path_exposure_journal&&) noexcept -> path_exposure_journal&;
    ~path_exposure_journal();

    [[nodiscard]] static auto open(
        const std::filesystem::path& path,
        std::uint64_t max_bytes = default_path_exposure_journal_bytes
    ) -> result<path_exposure_journal>;

    [[nodiscard]] auto records() const -> const std::vector<path_exposure_journal_record>&;

    [[nodiscard]] auto append(const path_exposure_journal_record& record)
        -> std::expected<void, std::string>;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::supervisor
