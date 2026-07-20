#include "glove/supervisor/change_apply_gate.hpp"

#include <string>
#include <utility>

namespace glove::supervisor {

namespace {

auto reserve_verified_change_apply(
    const change_apply_authorization& authorization,
    const retained_change_manifest& manifest,
    std::uint64_t now_ms,
    change_apply_journal& journal
) -> result<void> {
    const change_apply_reservation_record reservation{
        .grant_id = authorization.claims.grant_id,
        .authorization_digest = authorization.authorization_digest,
        .manifest_digest = manifest.manifest_digest,
        .session_id = manifest.session_id,
        .exposure_id = manifest.exposure_id,
        .generation = manifest.generation,
        .scope_digest = manifest.scope_digest,
        .source_identity_digest = manifest.source_identity_digest,
        .baseline_tree_digest = manifest.baseline_tree_digest,
        .staged_tree_digest = manifest.staged_tree_digest,
        .reserved_at_ms = now_ms,
    };
    return journal.reserve(reservation);
}

auto terminal_for(
    const change_apply_reservation_record& reservation,
    const change_apply_receipt& receipt,
    change_apply_terminal_state state
) -> change_apply_terminal_record {
    return {
        .grant_id = reservation.grant_id,
        .authorization_digest = reservation.authorization_digest,
        .manifest_digest = reservation.manifest_digest,
        .state = state,
        .receipt_digest = receipt.receipt_digest,
        .final_source_identity_digest = receipt.final_source_identity_digest,
        .failure_code = receipt.failure_code,
        .completed_at_ms = receipt.completed_at_ms,
    };
}

auto finalize_applied_observation(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    const change_apply_recovery_observation& observation,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result> {
    if (observation.state != change_apply_recovery_state::exchange_committed ||
        observation.source_tree_digest != reservation.staged_tree_digest ||
        !observation.candidate_tree_digest ||
        *observation.candidate_tree_digest != reservation.baseline_tree_digest) {
        return std::unexpected(std::string{"change apply recovery is not committed"});
    }
    change_apply_exchange_result exchange{
        .candidate_name = observation.candidate_name,
        .final_source_identity_digest = observation.current_source_identity_digest,
        .final_tree_digest = observation.source_tree_digest,
    };
    auto receipt = build_change_apply_receipt(reservation, exchange, completed_at_ms);
    if (!receipt) {
        return std::unexpected(receipt.error());
    }
    const auto terminal = terminal_for(reservation, *receipt, change_apply_terminal_state::applied);
    if (auto finalized = journal.finalize(terminal); !finalized) {
        return std::unexpected(finalized.error());
    }
    const bool cleanup_complete =
        cleanup_finalized_change_apply_baseline(reservation, terminal, manifest, target)
            .has_value();
    return finalized_change_apply_recovery_result{
        .exchange = std::move(exchange),
        .receipt = std::move(*receipt),
        .baseline_cleanup_complete = cleanup_complete,
    };
}

auto finalize_failed_observation(
    const change_apply_reservation_record& reservation,
    const change_apply_recovery_observation& observation,
    std::string_view failure_code,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result> {
    if (observation.state != change_apply_recovery_state::reserved ||
        observation.current_source_identity_digest != reservation.source_identity_digest ||
        observation.source_tree_digest != reservation.baseline_tree_digest ||
        observation.candidate_tree_digest) {
        return std::unexpected(std::string{"change apply failure state is not terminal-safe"});
    }
    auto receipt = build_failed_change_apply_receipt(
        reservation, observation.current_source_identity_digest, failure_code, completed_at_ms
    );
    if (!receipt) {
        return std::unexpected(receipt.error());
    }
    const auto terminal = terminal_for(reservation, *receipt, change_apply_terminal_state::failed);
    if (auto finalized = journal.finalize(terminal); !finalized) {
        return std::unexpected(finalized.error());
    }
    return finalized_change_apply_recovery_result{
        .exchange = std::nullopt,
        .receipt = std::move(*receipt),
        .baseline_cleanup_complete = true,
    };
}

auto recover_record(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    std::string_view failure_code,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result> {
    auto observation = inspect_change_apply_exchange_recovery(reservation, manifest, target);
    if (!observation) {
        return std::unexpected(observation.error());
    }
    if (observation->state == change_apply_recovery_state::exchange_committed) {
        return finalize_applied_observation(
            reservation, manifest, target, *observation, completed_at_ms, journal
        );
    }
    if (observation->state == change_apply_recovery_state::candidate_prepared) {
        if (auto discarded = discard_prepared_change_apply_candidate(reservation, manifest, target);
            !discarded) {
            return std::unexpected(discarded.error());
        }
        observation = inspect_change_apply_exchange_recovery(reservation, manifest, target);
        if (!observation) {
            return std::unexpected(observation.error());
        }
    }
    if (observation->state == change_apply_recovery_state::reserved) {
        return finalize_failed_observation(
            reservation, *observation, failure_code, completed_at_ms, journal
        );
    }
    return std::unexpected(std::string{"change apply recovery state is ambiguous"});
}

auto find_pending_record(
    const retained_change_manifest& manifest, const change_apply_journal& journal
) -> result<change_apply_reservation_record> {
    const auto records = journal.records();
    const change_apply_reservation_record* reservation = nullptr;
    for (const auto& candidate : records) {
        if (candidate.reservation.session_id != manifest.session_id ||
            candidate.reservation.exposure_id != manifest.exposure_id ||
            candidate.reservation.manifest_digest != manifest.manifest_digest ||
            candidate.terminal) {
            continue;
        }
        if (reservation != nullptr) {
            return std::unexpected(std::string{"pending change apply recovery is ambiguous"});
        }
        reservation = &candidate.reservation;
    }
    if (reservation == nullptr) {
        return std::unexpected(std::string{"pending change apply recovery is unavailable"});
    }
    return *reservation;
}

} // namespace

auto verify_and_reserve_change_apply(
    std::string_view canonical_authorization,
    const change_apply_authorization_context& expected,
    const retained_change_manifest& manifest,
    std::uint64_t now_ms,
    const change_apply_signature_verifier& verifier,
    change_apply_journal& journal
) -> result<change_apply_authorization> {
    auto decoded_manifest = decode_retained_change_manifest_json(manifest.canonical_json);
    if (!decoded_manifest || *decoded_manifest != manifest ||
        manifest.session_id != expected.session_id ||
        manifest.exposure_id != expected.exposure_id ||
        manifest.generation != expected.generation ||
        manifest.scope_digest != expected.scope_digest ||
        manifest.manifest_digest != expected.manifest_digest) {
        return std::unexpected(std::string{"change apply manifest context mismatch"});
    }
    auto authorization =
        verify_change_apply_authorization(canonical_authorization, expected, now_ms, verifier);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    if (auto reserved = reserve_verified_change_apply(*authorization, manifest, now_ms, journal);
        !reserved) {
        return std::unexpected(reserved.error());
    }
    return authorization;
}

auto execute_authorized_change_apply(
    std::string_view canonical_authorization,
    const change_apply_authorization_context& expected,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    int staged_descriptor,
    std::uint64_t now_ms,
    const change_apply_signature_verifier& verifier,
    change_apply_journal& journal
) -> result<authorized_change_apply_result> {
    auto decoded_manifest = decode_retained_change_manifest_json(manifest.canonical_json);
    if (!decoded_manifest || *decoded_manifest != manifest ||
        manifest.session_id != expected.session_id ||
        manifest.exposure_id != expected.exposure_id ||
        manifest.generation != expected.generation ||
        manifest.scope_digest != expected.scope_digest ||
        manifest.manifest_digest != expected.manifest_digest) {
        return std::unexpected(std::string{"change apply manifest context mismatch"});
    }
    auto authorization =
        verify_change_apply_authorization(canonical_authorization, expected, now_ms, verifier);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    if (auto valid =
            validate_change_apply_exchange_preconditions(manifest, target, staged_descriptor);
        !valid) {
        return std::unexpected(valid.error());
    }
    if (auto reserved = reserve_verified_change_apply(*authorization, manifest, now_ms, journal);
        !reserved) {
        return std::unexpected(reserved.error());
    }
    const auto stored = journal.find(authorization->claims.grant_id);
    if (!stored || stored->terminal) {
        return std::unexpected(std::string{"change apply reservation is unavailable"});
    }
    auto exchange =
        execute_change_apply_exchange(stored->reservation, manifest, target, staged_descriptor);
    if (!exchange) {
        auto recovered = recover_record(
            stored->reservation,
            manifest,
            target,
            "exchange_failed_before_mutation",
            now_ms,
            journal
        );
        if (!recovered) {
            return std::unexpected(exchange.error() + "; recovery required: " + recovered.error());
        }
        return authorized_change_apply_result{
            .authorization = std::move(*authorization),
            .exchange = std::move(recovered->exchange),
            .receipt = std::move(recovered->receipt),
            .baseline_cleanup_complete = recovered->baseline_cleanup_complete,
        };
    }
    auto receipt = build_change_apply_receipt(stored->reservation, *exchange, now_ms);
    if (!receipt) {
        return std::unexpected(receipt.error());
    }
    const auto terminal =
        terminal_for(stored->reservation, *receipt, change_apply_terminal_state::applied);
    if (auto finalized = journal.finalize(terminal); !finalized) {
        return std::unexpected(finalized.error());
    }
    const bool cleanup_complete =
        cleanup_finalized_change_apply_baseline(stored->reservation, terminal, manifest, target)
            .has_value();
    return authorized_change_apply_result{
        .authorization = std::move(*authorization),
        .exchange = std::move(*exchange),
        .receipt = std::move(*receipt),
        .baseline_cleanup_complete = cleanup_complete,
    };
}

auto recover_pending_change_apply(
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result> {
    auto reservation = find_pending_record(manifest, journal);
    if (!reservation) {
        return std::unexpected(reservation.error());
    }
    return recover_record(
        *reservation, manifest, target, "interrupted_before_mutation", completed_at_ms, journal
    );
}

auto reconcile_change_apply_journal(
    std::string_view materialization_root,
    const path_exposure_registry& path_exposures,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> change_apply_reconciliation_report {
    constexpr std::size_t max_issues = 256U;
    change_apply_reconciliation_report report;
    const auto add_issue = [&](const change_apply_reservation_record& reservation,
                               std::string code) {
        ++report.unresolved;
        if (report.issues.size() < max_issues) {
            report.issues.push_back({
                .grant_id = reservation.grant_id,
                .manifest_digest = reservation.manifest_digest,
                .code = std::move(code),
            });
        } else {
            report.issues_truncated = true;
        }
    };

    for (const auto& record : journal.records()) {
        const auto& reservation = record.reservation;
        if (record.terminal) {
            auto receipt = reconstruct_change_apply_receipt(reservation, *record.terminal);
            if (!receipt) {
                add_issue(reservation, "terminal_receipt_invalid");
                continue;
            }
            if (record.terminal->state == change_apply_terminal_state::failed) {
                continue;
            }
        }
        auto manifest = inspect_retained_change_stage(
            materialization_root, reservation.session_id, reservation.exposure_id
        );
        if (!manifest || manifest->manifest_digest != reservation.manifest_digest ||
            manifest->generation != reservation.generation ||
            manifest->scope_digest != reservation.scope_digest ||
            manifest->source_identity_digest != reservation.source_identity_digest) {
            add_issue(reservation, "stage_unavailable");
            continue;
        }
        auto target = path_exposures.resolve_recovery_target(
            reservation.exposure_id,
            reservation.generation,
            reservation.scope_digest,
            reservation.source_identity_digest
        );
        if (!target) {
            add_issue(reservation, "target_unavailable");
            continue;
        }
        if (record.terminal) {
            if (auto cleaned = cleanup_finalized_change_apply_baseline(
                    reservation, *record.terminal, *manifest, *target
                );
                cleaned) {
                ++report.cleanup_completed;
            } else {
                add_issue(reservation, "cleanup_pending");
            }
            continue;
        }
        auto recovered = recover_record(
            reservation, *manifest, *target, "interrupted_before_mutation", completed_at_ms, journal
        );
        if (!recovered) {
            add_issue(reservation, "recovery_ambiguous");
            continue;
        }
        if (recovered->receipt.state == "applied") {
            ++report.applied_finalized;
        } else {
            ++report.failed_finalized;
        }
        if (recovered->baseline_cleanup_complete) {
            ++report.cleanup_completed;
        } else {
            add_issue(reservation, "cleanup_pending");
        }
    }
    return report;
}

auto finalize_committed_change_apply_recovery(
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    std::uint64_t completed_at_ms,
    change_apply_journal& journal
) -> result<finalized_change_apply_recovery_result> {
    auto reservation = find_pending_record(manifest, journal);
    if (!reservation) {
        return std::unexpected(reservation.error());
    }
    auto observation = inspect_change_apply_exchange_recovery(*reservation, manifest, target);
    if (!observation || observation->state != change_apply_recovery_state::exchange_committed) {
        return std::unexpected(
            observation ? std::string{"change apply recovery is not committed"}
                        : observation.error()
        );
    }
    return finalize_applied_observation(
        *reservation, manifest, target, *observation, completed_at_ms, journal
    );
}

} // namespace glove::supervisor
