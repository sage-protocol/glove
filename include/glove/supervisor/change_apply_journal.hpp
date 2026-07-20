#pragma once

#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

inline constexpr std::uint64_t default_change_apply_journal_bytes =
    std::uint64_t{8} * 1024U * 1024U;

struct change_apply_reservation_record {
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::uint64_t reserved_at_ms = 0;

    auto operator==(const change_apply_reservation_record&) const -> bool = default;
};

enum class change_apply_terminal_state : std::uint8_t {
    applied,
    rejected,
    failed,
};

struct change_apply_terminal_record {
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    change_apply_terminal_state state = change_apply_terminal_state::failed;
    std::string receipt_digest;
    std::string final_source_identity_digest;
    std::string failure_code;
    std::uint64_t completed_at_ms = 0;

    auto operator==(const change_apply_terminal_record&) const -> bool = default;
};

struct change_apply_grant_status {
    change_apply_reservation_record reservation;
    std::optional<change_apply_terminal_record> terminal;
};

// Owner-only, bounded, append-only consumption ledger. reserve() is synced
// before a future apply engine may mutate the host. A reservation without a
// terminal record remains consumed after recovery and must never be retried.
class change_apply_journal final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class change_apply_journal;
    };

    change_apply_journal(construction_token token, std::unique_ptr<implementation> state);
    change_apply_journal(const change_apply_journal&) = delete;
    auto operator=(const change_apply_journal&) -> change_apply_journal& = delete;
    change_apply_journal(change_apply_journal&&) noexcept;
    auto operator=(change_apply_journal&&) noexcept -> change_apply_journal&;
    ~change_apply_journal();

    [[nodiscard]] static auto open(
        const std::filesystem::path& path,
        std::uint64_t max_bytes = default_change_apply_journal_bytes
    ) -> result<change_apply_journal>;

    [[nodiscard]] auto records() const -> std::vector<change_apply_grant_status>;

    [[nodiscard]] auto find(std::string_view grant_id) const
        -> std::optional<change_apply_grant_status>;

    // Grant IDs, authorization digests, and exact manifest digests are
    // globally single-use, including after terminal finalization.
    [[nodiscard]] auto reserve(const change_apply_reservation_record& record) -> result<void>;

    [[nodiscard]] auto finalize(const change_apply_terminal_record& record) -> result<void>;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::supervisor
