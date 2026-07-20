#pragma once

#include "glove/supervisor/change_apply_journal.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace glove::supervisor {

enum class change_apply_recovery_state : std::uint8_t {
    reserved,
    candidate_prepared,
    exchange_committed,
    ambiguous,
};

// The full authorization digest keeps transaction names deterministic and
// collision-resistant while remaining below the filesystem component bound.
[[nodiscard]] auto change_apply_candidate_name(std::string_view authorization_digest)
    -> result<std::string>;

// Infer only states that are unambiguous under the documented exchange
// protocol. Missing or unexpected objects never trigger an automatic retry.
[[nodiscard]] auto classify_change_apply_recovery(
    const change_apply_reservation_record& reservation,
    std::string_view source_tree_digest,
    const std::optional<std::string>& candidate_tree_digest
) -> change_apply_recovery_state;

} // namespace glove::supervisor
