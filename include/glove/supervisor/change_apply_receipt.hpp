#pragma once

#include "glove/supervisor/change_apply_exchange.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace glove::supervisor {

inline constexpr std::uint8_t change_apply_receipt_schema_version = 1;

struct change_apply_receipt {
    std::uint8_t schema_version = change_apply_receipt_schema_version;
    std::string state = "applied";
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string final_source_identity_digest;
    std::string failure_code;
    std::uint64_t completed_at_ms = 0;
    std::string receipt_digest;
    std::string canonical_json;

    auto operator==(const change_apply_receipt&) const -> bool = default;
};

[[nodiscard]] auto build_change_apply_receipt(
    const change_apply_reservation_record& reservation,
    const change_apply_exchange_result& exchange,
    std::uint64_t completed_at_ms
) -> result<change_apply_receipt>;

// Construct a terminal receipt only after descriptor inspection proves that
// the live source still matches the reserved baseline and no candidate remains.
[[nodiscard]] auto build_failed_change_apply_receipt(
    const change_apply_reservation_record& reservation,
    std::string_view final_source_identity_digest,
    std::string_view failure_code,
    std::uint64_t completed_at_ms
) -> result<change_apply_receipt>;

[[nodiscard]] auto decode_change_apply_receipt(std::string_view canonical_json)
    -> result<change_apply_receipt>;

// Recreate and authenticate a canonical receipt from the append-only journal
// after restart. Terminal records deliberately retain every outcome field
// needed for this reconstruction.
[[nodiscard]] auto reconstruct_change_apply_receipt(
    const change_apply_reservation_record& reservation, const change_apply_terminal_record& terminal
) -> result<change_apply_receipt>;

} // namespace glove::supervisor
