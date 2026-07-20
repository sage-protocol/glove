#pragma once

#include "cgroup_v2.hpp"
#include "session_reconciliation.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace glove::control::linux_detail {

// Linux restart policy: exact live sessions are terminated through their
// identity-matched cgroup, while absent sessions receive idempotent cgroup and
// filesystem cleanup. Mismatches are reported without side effects.
[[nodiscard]] auto reconcile_linux_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    container::linux_detail::cgroup_v2_root& cgroup_root,
    std::string_view materialization_root,
    std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string>;

} // namespace glove::control::linux_detail
