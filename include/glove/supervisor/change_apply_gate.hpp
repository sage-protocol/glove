#pragma once

#include "glove/supervisor/change_apply_authorization.hpp"
#include "glove/supervisor/change_apply_exchange.hpp"
#include "glove/supervisor/change_apply_journal.hpp"
#include "glove/supervisor/change_apply_receipt.hpp"
#include "glove/supervisor/change_manifest.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

// Sole pre-mutation gate: revalidate the canonical manifest, verify every
// signed binding, then durably consume the authorization. A successful return
// means the grant is already single-use even if later preparation fails.
[[nodiscard]] auto verify_and_reserve_change_apply(
    std::string_view canonical_authorization,
    const change_apply_authorization_context& expected,
    const retained_change_manifest& manifest,
    std::uint64_t now_ms,
    const change_apply_signature_verifier& verifier,
    change_apply_journal& journal
) -> result<change_apply_authorization>;

struct authorized_change_apply_result {
    change_apply_authorization authorization;
    std::optional<change_apply_exchange_result> exchange;
    change_apply_receipt receipt;
    bool baseline_cleanup_complete = false;
};

struct finalized_change_apply_recovery_result {
    std::optional<change_apply_exchange_result> exchange;
    change_apply_receipt receipt;
    bool baseline_cleanup_complete = false;
};

struct change_apply_reconciliation_issue {
    std::string grant_id;
    std::string manifest_digest;
    std::string code;

    auto operator==(const change_apply_reconciliation_issue&) const -> bool = default;
};

struct change_apply_reconciliation_report {
    std::uint64_t applied_finalized = 0;
    std::uint64_t failed_finalized = 0;
    std::uint64_t cleanup_completed = 0;
    std::uint64_t unresolved = 0;
    bool issues_truncated = false;
    std::vector<change_apply_reconciliation_issue> issues;
};

// Compose the only valid mutation order: authenticate and reserve, atomically
// exchange, construct the digest-bound receipt, then durably finalize. A
// descriptor-proven pre-mutation failure returns a terminal failed receipt and
// no exchange. A proven committed exchange returns an applied receipt. An
// ambiguous failure remains consumed and non-terminal for local recovery.
[[nodiscard]] auto execute_authorized_change_apply(
    std::string_view canonical_authorization,
    const change_apply_authorization_context& expected,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    int staged_descriptor,
    std::uint64_t now_ms,
    const change_apply_signature_verifier& verifier,
    change_apply_journal& journal
) -> result<authorized_change_apply_result>;

// Resolve one matching pending record without retrying its mutation. Reserved
// and safely discarded prepared states become terminal failures; a committed
// exchange becomes terminal applied; ambiguous states remain non-terminal.
[[nodiscard]] auto recover_pending_change_apply(
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result>;

// Bounded startup sweep over the append-only apply journal. It resolves only
// exact locally retained stages and exposure generations, reconstructs every
// existing terminal receipt before cleanup, and never retries an ambiguous
// mutation. Per-record failures are reported as stable redacted issue codes.
[[nodiscard]] auto reconcile_change_apply_journal(
    std::string_view materialization_root,
    const path_exposure_registry& path_exposures,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> change_apply_reconciliation_report;

// Finalize a crash-recovered exchange only when descriptor inspection proves
// staged-at-source and baseline-at-candidate. It does not resume a merely
// prepared candidate or mutate an ambiguous tree.
[[nodiscard]] auto finalize_committed_change_apply_recovery(
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result>;

} // namespace glove::supervisor
