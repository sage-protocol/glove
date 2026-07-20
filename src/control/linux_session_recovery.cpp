#include "linux_session_recovery.hpp"

#include "glove/supervisor/linux_session_filesystem.hpp"

#include "linux_process_identity.hpp"

#include <unistd.h>

#include <cstdint>
#include <expected>
#include <string>
#include <utility>
#include <vector>

namespace glove::control::linux_detail {

namespace {

auto cleanup_filesystem(
    const session_recovery_record& candidate, std::string_view materialization_root
) -> std::expected<void, std::string> {
    if (!candidate.filesystem_identity) {
        return std::unexpected(
            std::string{"running recovery candidate has no filesystem identity"}
        );
    }
    std::vector<supervisor::linux_detail::recovered_quota_partition> partitions;
    partitions.reserve(candidate.filesystem_identity->partitions.size());
    for (const auto& partition : candidate.filesystem_identity->partitions) {
        partitions.push_back({
            .alias = partition.alias,
            .quota_bytes = partition.quota_bytes,
        });
    }
    return supervisor::linux_detail::linux_session_filesystem::cleanup_recovered(
        materialization_root,
        candidate.session.session_id,
        candidate.filesystem_identity->disk_limit_bytes,
        partitions
    );
}

auto wait_until_absent(const linux_process_identity& identity) -> std::expected<void, std::string> {
    for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
        auto observation = observe_linux_process_identity(identity);
        if (!observation) {
            return std::unexpected(observation.error());
        }
        if (*observation == linux_process_identity_observation::absent) {
            return {};
        }
        if (*observation == linux_process_identity_observation::mismatch) {
            return std::unexpected(
                std::string{"terminated Linux process identity was replaced before cleanup"}
            );
        }
        ::usleep(10U * 1000U);
    }
    return std::unexpected(std::string{"terminated Linux process remained observable"});
}

} // namespace

auto reconcile_linux_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    container::linux_detail::cgroup_v2_root& cgroup_root,
    std::string_view materialization_root,
    std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string> {
    if (materialization_root.empty()) {
        return std::unexpected(std::string{"Linux recovery materialization root is required"});
    }
    auto candidates = registry.recovery_candidates();
    if (!candidates) {
        return std::unexpected(
            std::string{"inventory Linux recovery resources: "} + candidates.error().message
        );
    }
    std::vector<std::string> protected_sessions;
    protected_sessions.reserve(candidates->size());
    for (const auto& candidate : *candidates) {
        protected_sessions.push_back(candidate.session.session_id);
    }
    auto swept = supervisor::linux_detail::linux_session_filesystem::sweep_orphaned(
        materialization_root, protected_sessions
    );
    if (!swept) {
        return std::unexpected(
            std::string{"recover orphaned Linux materializations: "} + swept.error()
        );
    }
    for (const auto& candidate : *candidates) {
        if (candidate.session.state != session_state::starting) {
            continue;
        }
        if (!candidate.cgroup_identity || !candidate.filesystem_identity) {
            return std::unexpected(
                std::string{"starting recovery candidate has incomplete resource identity"}
            );
        }
        if (auto cleaned = cgroup_root.cleanup_session_if_matches(
                candidate.session.session_id,
                candidate.cgroup_identity->device,
                candidate.cgroup_identity->inode
            );
            !cleaned) {
            return std::unexpected(cleaned.error());
        }
        if (auto cleaned = cleanup_filesystem(candidate, materialization_root); !cleaned) {
            return std::unexpected(cleaned.error());
        }
    }
    const session_process_observer observer = [&](const session_recovery_record& candidate)
        -> std::expected<session_process_observation, std::string> {
        if (!candidate.process_identity || !candidate.cgroup_identity ||
            !candidate.filesystem_identity) {
            return std::unexpected(
                std::string{"running recovery candidate has incomplete resource identity"}
            );
        }
        auto observed = observe_linux_process_identity(*candidate.process_identity);
        if (!observed) {
            return std::unexpected(observed.error());
        }
        if (*observed == linux_process_identity_observation::mismatch) {
            return session_process_observation::mismatch;
        }
        if (*observed == linux_process_identity_observation::absent) {
            if (auto cleaned = cgroup_root.cleanup_session_if_matches(
                    candidate.session.session_id,
                    candidate.cgroup_identity->device,
                    candidate.cgroup_identity->inode
                );
                !cleaned) {
                return std::unexpected(cleaned.error());
            }
            if (auto cleaned = cleanup_filesystem(candidate, materialization_root); !cleaned) {
                return std::unexpected(cleaned.error());
            }
            return session_process_observation::absent;
        }

        auto adopted = cgroup_root.adopt_session(
            candidate.session.session_id,
            candidate.cgroup_identity->device,
            candidate.cgroup_identity->inode
        );
        if (!adopted) {
            return std::unexpected(adopted.error());
        }
        auto confirmed = observe_linux_process_identity(*candidate.process_identity);
        if (!confirmed || *confirmed != linux_process_identity_observation::exact) {
            return std::unexpected(
                confirmed ? std::string{"Linux process identity changed during cgroup adoption"}
                          : confirmed.error()
            );
        }
        if (auto killed = adopted->kill_all(); !killed) {
            return std::unexpected(killed.error());
        }
        if (auto cleaned = adopted->cleanup(); !cleaned) {
            return std::unexpected(cleaned.error());
        }
        if (auto cleaned = cleanup_filesystem(candidate, materialization_root); !cleaned) {
            return std::unexpected(cleaned.error());
        }
        if (auto absent = wait_until_absent(*candidate.process_identity); !absent) {
            return std::unexpected(absent.error());
        }
        return session_process_observation::terminated;
    };
    auto reconciled = reconcile_session_registry(registry, receipt_producer, now_ms, observer);
    if (!reconciled) {
        return std::unexpected(reconciled.error());
    }
    reconciled->orphan_materializations_inspected = swept->inspected;
    reconciled->orphan_materializations_removed = swept->removed_without_stage;
    reconciled->orphan_retained_changes_recovered = swept->recovered_retained_changes.size();
    return reconciled;
}

} // namespace glove::control::linux_detail
