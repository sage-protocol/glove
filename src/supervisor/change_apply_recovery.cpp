#include "glove/supervisor/change_apply_recovery.hpp"

#include <algorithm>
#include <string>
#include <string_view>

namespace glove::supervisor {

namespace {

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

} // namespace

auto change_apply_candidate_name(std::string_view authorization_digest) -> result<std::string> {
    if (!valid_digest(authorization_digest)) {
        return std::unexpected(std::string{"change apply authorization digest is invalid"});
    }
    return ".glove-apply-v1-" + std::string{authorization_digest};
}

auto classify_change_apply_recovery(
    const change_apply_reservation_record& reservation,
    std::string_view source_tree_digest,
    const std::optional<std::string>& candidate_tree_digest
) -> change_apply_recovery_state {
    if (!valid_digest(reservation.baseline_tree_digest) ||
        !valid_digest(reservation.staged_tree_digest) || !valid_digest(source_tree_digest) ||
        (candidate_tree_digest && !valid_digest(*candidate_tree_digest))) {
        return change_apply_recovery_state::ambiguous;
    }
    if (!candidate_tree_digest) {
        return source_tree_digest == reservation.baseline_tree_digest
                   ? change_apply_recovery_state::reserved
                   : change_apply_recovery_state::ambiguous;
    }
    if (source_tree_digest == reservation.baseline_tree_digest &&
        *candidate_tree_digest == reservation.staged_tree_digest) {
        return change_apply_recovery_state::candidate_prepared;
    }
    if (source_tree_digest == reservation.staged_tree_digest &&
        *candidate_tree_digest == reservation.baseline_tree_digest) {
        return change_apply_recovery_state::exchange_committed;
    }
    return change_apply_recovery_state::ambiguous;
}

} // namespace glove::supervisor
