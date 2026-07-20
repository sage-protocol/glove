#pragma once

#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/linux_ephemeral_copy.hpp"
#include "glove/supervisor/path_alias.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor::linux_detail {

struct session_mount {
    int descriptor_fd = -1;
    std::string target_path;
    std::string alias;
    std::string quota_partition;
    std::uint64_t quota_bytes = 0;
    std::optional<path_identity> source_identity;
    std::optional<std::string> source_content_digest;
    std::optional<std::string> projection_id;
    std::optional<std::string> projection_destination_alias;
    bool writable = false;
    bool directory = false;
};

struct session_filesystem_usage {
    std::uint64_t filesystem_bytes = 0;
    std::uint64_t quota_bytes = 0;
    std::size_t materializations = 0;
    bool limit_hit = false;
};

struct recovered_quota_partition {
    std::string alias;
    std::uint64_t quota_bytes = 0;

    auto operator==(const recovered_quota_partition&) const -> bool = default;
};

// Owns every filesystem exposed to one session. Read grants remain pinned,
// descriptor-cloned host objects and consume no write quota. Each ephemeral
// write alias keeps its host-configured quota and the remaining capacity backs
// shared /tmp and /var/tmp directories. Because writable partition capacities
// sum exactly to the session limit, aggregate writes cannot exceed that limit.
class linux_session_filesystem {
public:
    linux_session_filesystem(const linux_session_filesystem&) = delete;
    auto operator=(const linux_session_filesystem&) -> linux_session_filesystem& = delete;
    linux_session_filesystem(linux_session_filesystem&& other) noexcept;
    auto operator=(linux_session_filesystem&&) -> linux_session_filesystem& = delete;
    ~linux_session_filesystem();

    [[nodiscard]] static result<linux_session_filesystem> create(
        std::string_view materialization_root,
        std::string_view session_id,
        std::uint64_t disk_limit_bytes,
        std::vector<resolved_path_grant>&& grants,
        std::vector<resolved_library_projection>&& library_projections = {}
    );

    // Removes only the deterministic tmpfs partitions whose complete quota
    // layout still matches the durable canonical plan. Every present partition
    // is preflighted before cleanup begins; absent partitions make retries
    // idempotent.
    [[nodiscard]] static result<void> cleanup_recovered(
        std::string_view materialization_root,
        std::string_view session_id,
        std::uint64_t disk_limit_bytes,
        const std::vector<recovered_quota_partition>& partitions
    );

    [[nodiscard]] auto mounts() const -> std::vector<session_mount>;

    [[nodiscard]] auto disk_limit_bytes() const noexcept -> std::uint64_t {
        return active_ ? disk_limit_bytes_ : 0;
    }

    [[nodiscard]] auto recovery_partitions() const -> std::vector<recovered_quota_partition>;
    [[nodiscard]] result<session_filesystem_usage> observe() const;
    [[nodiscard]] result<void> cleanup();

private:
    linux_session_filesystem(
        std::uint64_t disk_limit_bytes,
        ephemeral_copy_materialization scratch,
        int tmp_fd,
        int var_tmp_fd,
        std::vector<ephemeral_copy_materialization> materializations,
        std::vector<session_mount> mounts
    ) noexcept;

    void close_scratch_descriptors() noexcept;
    void close_mount_descriptors() noexcept;

    std::uint64_t disk_limit_bytes_ = 0;
    ephemeral_copy_materialization scratch_;
    int tmp_fd_ = -1;
    int var_tmp_fd_ = -1;
    std::vector<ephemeral_copy_materialization> materializations_;
    std::vector<session_mount> mounts_;
    bool active_ = true;
};

} // namespace glove::supervisor::linux_detail
