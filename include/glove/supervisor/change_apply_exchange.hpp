#pragma once

#include "glove/supervisor/change_apply_journal.hpp"
#include "glove/supervisor/change_apply_recovery.hpp"
#include "glove/supervisor/change_manifest.hpp"
#include "glove/supervisor/path_exposure.hpp"

#include <optional>
#include <string>

namespace glove::supervisor {

inline constexpr std::uint64_t default_change_apply_free_space_reserve_bytes =
    std::uint64_t{64} * 1024U * 1024U;

// Pure policy predicate shared with boundary tests. Candidate bytes are the
// complete logical staged tree; the reserve covers filesystem metadata and
// preserves operator headroom after the sibling copy.
[[nodiscard]] auto change_apply_host_space_eligible(
    std::uint64_t available_bytes,
    std::uint64_t candidate_bytes,
    std::uint64_t reserve_bytes = default_change_apply_free_space_reserve_bytes
) noexcept -> bool;

struct change_apply_exchange_result {
    std::string candidate_name;
    std::string final_source_identity_digest;
    std::string final_tree_digest;

    auto operator==(const change_apply_exchange_result&) const -> bool = default;
};

struct change_apply_recovery_observation {
    change_apply_recovery_state state = change_apply_recovery_state::ambiguous;
    std::string candidate_name;
    std::string current_source_identity_digest;
    std::string source_tree_digest;
    std::optional<std::string> candidate_tree_digest;

    auto operator==(const change_apply_recovery_observation&) const -> bool = default;
};

// Fail-closed eligibility check performed before consuming an authorization.
// The current source and frozen stage must use Glove's deliberately narrow
// metadata profile, match the signed manifest, and live beneath a parent that
// is not writable outside the dedicated Glove service identity. Execution
// repeats these checks after reservation before mutation.
[[nodiscard]] auto validate_change_apply_exchange_preconditions(
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    int staged_descriptor
) -> result<void>;

// Linux-only whole-entry apply primitive. The authorization must already have
// been verified and durably reserved by verify_and_reserve_change_apply(). It
// copies the staged tree into a deterministic sibling, validates both tree
// digests and the original source identity, then atomically swaps the sibling
// with the live entry. The sibling containing the baseline is deliberately
// retained until a terminal journal record and receipt are durable.
//
// No manifest-entry replay occurs. A failure after the exchange is treated as
// recovery-required; this function never guesses whether it is safe to delete
// or replay a candidate.
[[nodiscard]] auto execute_change_apply_exchange(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    int staged_descriptor
) -> result<change_apply_exchange_result>;

// Descriptor-only recovery inspection for a durably reserved transaction. It
// performs no mutation and never treats an inspection error as permission to
// retry. Callers may automatically finalize only states covered by their local
// recovery policy; ambiguous results require operator repair.
[[nodiscard]] auto inspect_change_apply_exchange_recovery(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<change_apply_recovery_observation>;

// Idempotently remove the baseline sibling only after an applied terminal
// record is durable. The live source, terminal final identity, staged digest,
// and candidate baseline digest are all revalidated before deletion. This is
// also the startup-recovery cleanup primitive.
[[nodiscard]] auto cleanup_finalized_change_apply_baseline(
    const change_apply_reservation_record& reservation,
    const change_apply_terminal_record& terminal,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<void>;

// Remove a fully prepared staged candidate only while the live source still
// proves the reserved baseline. No terminal failure may be recorded until this
// returns and a second inspection proves the plain reserved state.
[[nodiscard]] auto discard_prepared_change_apply_candidate(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<void>;

} // namespace glove::supervisor
