#pragma once

#include "glove/container/receipt_producer.hpp"
#include "glove/control/session_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace glove::control {

enum class session_process_observation : std::uint8_t {
    exact,
    absent,
    mismatch,
    terminated,
};

using session_process_observer = std::function<
    std::expected<session_process_observation, std::string>(const session_recovery_record&)>;

struct session_reconciliation_report {
    std::size_t inspected = 0;
    std::size_t recovered_exited = 0;
    std::size_t recovered_failed = 0;
    std::size_t recovered_terminated = 0;
    std::size_t orphan_materializations_inspected = 0;
    std::size_t orphan_materializations_removed = 0;
    std::size_t orphan_retained_changes_recovered = 0;
    std::vector<std::string> unresolved_running_session_ids;
    std::vector<std::string> live_running_session_ids;
    std::vector<std::string> identity_mismatch_session_ids;

    auto operator==(const session_reconciliation_report&) const -> bool = default;
};

// Startup-only registry/journal repair. A starting child was never released,
// so it can be closed as recovered_without_process. A running session is
// terminalized only from its exact durable authenticated receipt. On Linux,
// receipt-less running records are classified from the complete durable process
// identity; PID alone is never authority. Other platforms report them as
// unresolved until they provide an equivalent observer.
[[nodiscard]] auto reconcile_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string>;

// Observer-injected form used by the Linux daemon and deterministic tests. An
// absent exact identity is closed without signaling any process. A mismatch is
// reported but remains running until exact cgroup ownership can be resolved.
[[nodiscard]] auto reconcile_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms,
    const session_process_observer& process_observer
) -> std::expected<session_reconciliation_report, std::string>;

} // namespace glove::control
