#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace glove::supervisor {

template<typename Value> using result = std::expected<Value, std::string>;

enum class path_access : std::uint8_t {
    read,
    ephemeral_write,
    retained_write,
    // Legacy v1 policy value. It is validation-only and cannot be resolved.
    direct_write,
};

enum class path_materialization : std::uint8_t {
    bind,
    snapshot,
    git_worktree,
    copy,
};

enum class path_create_policy : std::uint8_t {
    never,
    empty_directory,
    git_worktree,
};

enum class path_cleanup_policy : std::uint8_t {
    retain,
    remove,
};

struct path_access_policy {
    path_access access = path_access::read;
    path_materialization materialization = path_materialization::bind;
    path_create_policy create_policy = path_create_policy::never;
    path_cleanup_policy cleanup_policy = path_cleanup_policy::retain;
    std::uint64_t max_bytes = 0;
};

// Host-owned configuration. Remote requests refer only to `alias`; neither the
// host path nor a remotely selected target path crosses the control boundary.
struct path_alias_policy {
    std::string alias;
    std::string host_path;
    std::string target_path;
    std::uint64_t max_ttl_secs = 0;
    std::vector<path_access_policy> access;
};

struct path_grant_request {
    std::string alias;
    path_access access = path_access::read;
    std::uint64_t ttl_secs = 0;
    std::uint64_t max_bytes = 0;
};

// Read-only projection check used while validating an immutable controller
// plan. This proves that the requested policy is present and that the current
// host object is safe to resolve, but deliberately returns no descriptor and
// therefore grants no launch authority. In particular, direct-write can be
// recognized here while remaining unavailable through `resolve` until its
// authenticated local approval is bound to session creation.
struct path_grant_plan_request {
    path_grant_request grant;
    path_materialization materialization = path_materialization::bind;
    path_cleanup_policy cleanup_policy = path_cleanup_policy::retain;
};

struct path_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint32_t mode = 0;

    auto operator==(const path_identity&) const -> bool = default;
};

// A pinned host object plus its immutable, remote-safe grant projection. The
// descriptor is borrowed by callers and remains owned by this object.
class resolved_path_grant {
public:
    resolved_path_grant(const resolved_path_grant&) = delete;
    auto operator=(const resolved_path_grant&) -> resolved_path_grant& = delete;
    resolved_path_grant(resolved_path_grant&& other) noexcept;
    auto operator=(resolved_path_grant&& other) noexcept -> resolved_path_grant&;
    ~resolved_path_grant();

    [[nodiscard]] auto descriptor_fd() const noexcept -> int { return descriptor_fd_; }

    [[nodiscard]] auto alias() const noexcept -> std::string_view { return alias_; }

    [[nodiscard]] auto target_path() const noexcept -> std::string_view { return target_path_; }

    [[nodiscard]] auto access() const noexcept -> path_access { return access_; }

    [[nodiscard]] auto materialization() const noexcept -> path_materialization {
        return materialization_;
    }

    [[nodiscard]] auto create_policy() const noexcept -> path_create_policy {
        return create_policy_;
    }

    [[nodiscard]] auto cleanup_policy() const noexcept -> path_cleanup_policy {
        return cleanup_policy_;
    }

    [[nodiscard]] auto ttl_secs() const noexcept -> std::uint64_t { return ttl_secs_; }

    [[nodiscard]] auto max_bytes() const noexcept -> std::uint64_t { return max_bytes_; }

    [[nodiscard]] auto identity() const noexcept -> path_identity { return identity_; }

    [[nodiscard]] auto exposure_generation() const noexcept -> std::uint64_t {
        return exposure_generation_;
    }

    [[nodiscard]] auto exposure_scope_digest() const noexcept -> std::string_view {
        return exposure_scope_digest_;
    }

    [[nodiscard]] auto source_identity_digest() const noexcept -> std::string_view {
        return source_identity_digest_;
    }

    // Re-open through the host-configured component chain with O_NOFOLLOW and
    // reject if the object at the alias changed after planning.
    [[nodiscard]] auto verify_identity() const -> std::expected<void, std::string>;

private:
    friend class path_alias_registry;
    friend class path_exposure_registry;

    resolved_path_grant(
        int descriptor_fd,
        std::string alias,
        std::string host_path,
        std::string target_path,
        const path_access_policy& policy,
        const path_grant_request& request,
        path_identity identity,
        std::uint64_t exposure_generation = 0,
        std::string exposure_scope_digest = {},
        std::string source_identity_digest = {}
    );

    void close_descriptor() noexcept;

    int descriptor_fd_ = -1;
    std::string alias_;
    std::string host_path_;
    std::string target_path_;
    path_access access_ = path_access::read;
    path_materialization materialization_ = path_materialization::bind;
    path_create_policy create_policy_ = path_create_policy::never;
    path_cleanup_policy cleanup_policy_ = path_cleanup_policy::retain;
    std::uint64_t ttl_secs_ = 0;
    std::uint64_t max_bytes_ = 0;
    path_identity identity_;
    std::uint64_t exposure_generation_ = 0;
    std::string exposure_scope_digest_;
    std::string source_identity_digest_;
};

class path_alias_registry {
public:
    [[nodiscard]] static result<path_alias_registry> build(std::vector<path_alias_policy> policies);

    [[nodiscard]] auto validate_plan(const path_grant_plan_request& request) const
        -> std::expected<void, std::string>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return policies_.size(); }

    // Direct-write resolution deliberately has no generic boolean escape
    // hatch. It remains unavailable until the authenticated local approval
    // record is part of the supervisor API.
    [[nodiscard]] result<resolved_path_grant> resolve(const path_grant_request& request) const;

private:
    std::unordered_map<std::string, path_alias_policy> policies_;
};

} // namespace glove::supervisor
