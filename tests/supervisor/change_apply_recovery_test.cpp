#include "glove/supervisor/change_apply_recovery.hpp"

#include <cstdio>
#include <optional>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

auto run() -> int {
    using namespace glove::supervisor;

    const change_apply_reservation_record reservation{
        .grant_id = "grant-1",
        .authorization_digest = std::string(64, 'a'),
        .manifest_digest = std::string(64, 'b'),
        .session_id = "session-1",
        .exposure_id = "workspace",
        .generation = 7,
        .scope_digest = std::string(64, 'c'),
        .source_identity_digest = std::string(64, 'd'),
        .baseline_tree_digest = std::string(64, 'e'),
        .staged_tree_digest = std::string(64, 'f'),
        .reserved_at_ms = 1'000,
    };
    auto name = change_apply_candidate_name(reservation.authorization_digest);
    REQUIRE(name.has_value());
    REQUIRE(*name == ".glove-apply-v1-" + reservation.authorization_digest);
    REQUIRE(!change_apply_candidate_name("bad").has_value());

    REQUIRE(
        classify_change_apply_recovery(
            reservation, reservation.baseline_tree_digest, std::nullopt
        ) == change_apply_recovery_state::reserved
    );
    REQUIRE(
        classify_change_apply_recovery(
            reservation, reservation.baseline_tree_digest, reservation.staged_tree_digest
        ) == change_apply_recovery_state::candidate_prepared
    );
    REQUIRE(
        classify_change_apply_recovery(
            reservation, reservation.staged_tree_digest, reservation.baseline_tree_digest
        ) == change_apply_recovery_state::exchange_committed
    );
    REQUIRE(
        classify_change_apply_recovery(reservation, reservation.staged_tree_digest, std::nullopt) ==
        change_apply_recovery_state::ambiguous
    );
    REQUIRE(
        classify_change_apply_recovery(
            reservation, reservation.baseline_tree_digest, reservation.baseline_tree_digest
        ) == change_apply_recovery_state::ambiguous
    );
    REQUIRE(
        classify_change_apply_recovery(reservation, "bad", std::nullopt) ==
        change_apply_recovery_state::ambiguous
    );
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
