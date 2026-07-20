#pragma once

#include "glove/supervisor/change_manifest.hpp"
#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace glove::supervisor::linux_detail {

class linux_session_filesystem;

struct materialization_usage {
    std::uint64_t logical_bytes = 0;
    std::uint64_t filesystem_bytes = 0;
    std::uint64_t quota_bytes = 0;
    std::uint64_t regular_files = 0;
    std::uint64_t directories = 0;
};

// One quota-backed copy materialization. The configured root is local Glove
// state, never remote input. The borrowed content descriptor remains valid
// until cleanup or destruction.
class ephemeral_copy_materialization {
public:
    ephemeral_copy_materialization(const ephemeral_copy_materialization&) = delete;
    ephemeral_copy_materialization& operator=(const ephemeral_copy_materialization&) = delete;
    ephemeral_copy_materialization(ephemeral_copy_materialization&& other) noexcept;
    auto operator=(ephemeral_copy_materialization&&) -> ephemeral_copy_materialization& = delete;
    ~ephemeral_copy_materialization();

    [[nodiscard]] static result<ephemeral_copy_materialization> create(
        std::string_view materialization_root,
        std::string_view session_id,
        const resolved_path_grant& grant
    );

    [[nodiscard]] auto content_fd() const noexcept -> int { return content_fd_; }

    [[nodiscard]] auto target_path() const noexcept -> std::string_view { return target_path_; }

    [[nodiscard]] auto alias() const noexcept -> std::string_view { return alias_; }

    [[nodiscard]] auto is_directory() const noexcept -> bool { return is_directory_; }

    [[nodiscard]] auto quota_bytes() const noexcept -> std::uint64_t { return quota_bytes_; }

    [[nodiscard]] auto source_identity() const noexcept -> std::optional<path_identity> {
        return source_identity_;
    }

    [[nodiscard]] result<materialization_usage> observe() const;
    [[nodiscard]] result<std::optional<retained_change_manifest>> finalize_retained();
    [[nodiscard]] result<void> cleanup();

private:
    friend class linux_session_filesystem;

    [[nodiscard]] static result<ephemeral_copy_materialization> create_mounted(
        std::string_view materialization_root,
        std::string directory_name,
        std::string target_path,
        std::string alias,
        std::uint64_t quota_bytes,
        bool persistent
    );

    [[nodiscard]] static result<ephemeral_copy_materialization> create_empty_session_scratch(
        std::string_view materialization_root,
        std::string_view session_id,
        std::uint64_t quota_bytes
    );

    [[nodiscard]] static result<std::optional<ephemeral_copy_materialization>> adopt_recovered(
        std::string_view materialization_root,
        std::string_view session_id,
        std::string directory_name,
        std::string alias,
        std::uint64_t quota_bytes
    );

    // Recovers one exact deterministic preparation orphan. Retained copies
    // with durable metadata are finalized before cleanup; incomplete retained
    // copies and volatile tmpfs mounts are removed without publication.
    [[nodiscard]] static result<std::optional<retained_change_manifest>> recover_orphaned(
        std::string_view materialization_root,
        std::string_view session_id,
        std::string directory_name,
        std::string alias
    );

    ephemeral_copy_materialization(
        int root_fd,
        int mount_root_fd,
        std::string directory_name,
        std::string mount_path,
        std::string target_path,
        std::string alias,
        std::uint64_t quota_bytes,
        bool cleanup_on_destroy
    ) noexcept;

    void arm_recovered_cleanup() noexcept { cleanup_on_destroy_ = true; }

    void close_content_descriptors() noexcept;
    void close_root_descriptor() noexcept;
    void cleanup_noexcept() noexcept;

    int root_fd_ = -1;
    int mount_root_fd_ = -1;
    int content_fd_ = -1;
    std::string directory_name_;
    std::string mount_path_;
    std::string target_path_;
    std::string alias_;
    std::uint64_t quota_bytes_ = 0;
    std::uint64_t logical_bytes_ = 0;
    std::uint64_t regular_files_ = 0;
    std::uint64_t directories_ = 0;
    std::optional<path_identity> source_identity_;
    std::string session_id_;
    std::uint64_t exposure_generation_ = 0;
    std::string exposure_scope_digest_;
    std::string source_identity_digest_;
    std::vector<path_snapshot_entry> baseline_;
    std::optional<retained_change_manifest> retained_manifest_;
    std::string retained_metadata_name_;
    std::string persistent_image_name_;
    bool is_directory_ = false;
    bool persistent_ = false;
    bool mounted_ = false;
    bool cleanup_on_destroy_ = true;
};

} // namespace glove::supervisor::linux_detail
