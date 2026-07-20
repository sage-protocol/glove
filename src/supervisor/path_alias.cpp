#include "glove/supervisor/path_alias.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <filesystem>
#include <iterator>
#include <set>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace glove::supervisor {

namespace {

class unique_fd {
public:
    explicit unique_fd(int fd = -1) noexcept : fd_{fd} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(fd_, -1); }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

auto valid_alias(std::string_view alias) -> bool {
    return !alias.empty() && alias.size() <= 128 &&
           std::all_of(alias.begin(), alias.end(), [](char character) {
               const auto byte = static_cast<unsigned char>(character);
               return std::isalnum(byte) != 0 || character == '-' || character == '_' ||
                      character == '.';
           });
}

auto valid_absolute_path(std::string_view raw) -> bool {
    if (raw.empty()) {
        return false;
    }
    const std::filesystem::path path{raw};
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return false;
    }
    return std::none_of(path.begin(), path.end(), [](const auto& component) {
        return component == "." || component == "..";
    });
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& reserved)
    -> bool {
    const auto mismatch =
        std::mismatch(reserved.begin(), reserved.end(), candidate.begin(), candidate.end());
    return mismatch.first == reserved.end();
}

auto reserved_target(std::string_view raw) -> bool {
    const std::filesystem::path candidate{raw};
    constexpr std::array<std::string_view, 9> reserved = {
        "/bin", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin", "/sys", "/usr"
    };
    return std::ranges::any_of(reserved, [&](std::string_view root) {
        return path_within(candidate, std::filesystem::path{root});
    });
}

auto reserved_host(std::string_view raw) -> bool {
    const std::filesystem::path candidate{raw};
    constexpr std::array<std::string_view, 4> kernel_roots = {"/dev", "/proc", "/run", "/sys"};
    const auto is_kernel_root = [&](std::string_view root) {
        return path_within(candidate, std::filesystem::path{root});
    };
    if (std::ranges::any_of(kernel_roots, is_kernel_root)) {
        return true;
    }
    if (candidate == "/root" || candidate == "/var/root") {
        return true;
    }
    const auto relative = candidate.relative_path();
    if (std::distance(relative.begin(), relative.end()) == 2) {
        const auto first = relative.begin()->string();
        if (first == "home" || first == "Users") {
            return true;
        }
    }
    constexpr std::array<std::string_view, 6> secret_directories = {
        ".aws", ".azure", ".gnupg", ".kube", ".sage", ".ssh"
    };
    return std::ranges::any_of(candidate, [&](const auto& component) {
        const auto name = component.string();
        return std::ranges::find(secret_directories, name) != secret_directories.end();
    });
}

auto open_path_no_follow(std::string_view raw, std::string_view alias)
    -> std::expected<unique_fd, std::string> {
    const auto error_message = [](int error_number) {
        return std::error_code{error_number, std::generic_category()}.message();
    };
    unique_fd current{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (current.get() < 0) {
        return std::unexpected(std::string{"open alias root: "} + error_message(errno));
    }

    const std::filesystem::path path{raw};
    const auto relative = path.relative_path();
    for (auto component = relative.begin(); component != relative.end(); ++component) {
        const bool final = std::next(component) == relative.end();
        const std::string name = component->string();
#if defined(__linux__)
        int flags = O_PATH | O_CLOEXEC | O_NOFOLLOW;
#else
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
#endif
        if (!final) {
            flags |= O_DIRECTORY;
        }
        unique_fd next{::openat(current.get(), name.c_str(), flags)};
        if (next.get() < 0) {
            return std::unexpected(
                std::string{"resolve path alias '"} + std::string{alias} +
                "': " + error_message(errno)
            );
        }
        current = std::move(next);
    }

    struct ::stat status = {};
    if (::fstat(current.get(), &status) < 0) {
        return std::unexpected(
            std::string{"inspect path alias '"} + std::string{alias} + "': " + error_message(errno)
        );
    }
    if (S_ISLNK(status.st_mode)) {
        return std::unexpected(
            std::string{"path alias '"} + std::string{alias} + "' resolves to a symlink"
        );
    }
    if (!S_ISREG(status.st_mode) && !S_ISDIR(status.st_mode)) {
        return std::unexpected(
            std::string{"path alias '"} + std::string{alias} +
            "' must resolve to a regular file or directory"
        );
    }
    return current;
}

auto identity_for(int fd, std::string_view alias) -> std::expected<path_identity, std::string> {
    struct ::stat status = {};
    if (::fstat(fd, &status) < 0) {
        const auto message = std::error_code{errno, std::generic_category()}.message();
        return std::unexpected(
            std::string{"inspect path alias '"} + std::string{alias} + "': " + message
        );
    }
    using unsigned_device = std::make_unsigned_t<decltype(status.st_dev)>;
    using unsigned_inode = std::make_unsigned_t<decltype(status.st_ino)>;
    const auto device = static_cast<unsigned_device>(status.st_dev);
    const auto inode = static_cast<unsigned_inode>(status.st_ino);
    static_assert(sizeof(device) <= sizeof(std::uint64_t));
    static_assert(sizeof(inode) <= sizeof(std::uint64_t));
    static_assert(sizeof(status.st_mode) <= sizeof(std::uint32_t));
    return path_identity{
        .device = static_cast<std::uint64_t>(device),
        .inode = static_cast<std::uint64_t>(inode),
        .mode = static_cast<std::uint32_t>(status.st_mode),
    };
}

auto validate_access_policy(const path_access_policy& policy) -> std::expected<void, std::string> {
    if (policy.materialization == path_materialization::bind &&
        policy.create_policy != path_create_policy::never) {
        return std::unexpected(std::string{"bind materialization cannot create a target"});
    }
    if ((policy.materialization == path_materialization::git_worktree) !=
        (policy.create_policy == path_create_policy::git_worktree)) {
        return std::unexpected(std::string{"git worktree materialization/create policy mismatch"});
    }
    switch (policy.access) {
    case path_access::read:
        if (policy.max_bytes != 0) {
            return std::unexpected(std::string{"read access may not declare a write quota"});
        }
        if (policy.materialization == path_materialization::bind &&
            policy.cleanup_policy != path_cleanup_policy::retain) {
            return std::unexpected(std::string{"read bind must retain its host source"});
        }
        break;
    case path_access::ephemeral_write:
        if (policy.materialization == path_materialization::bind || policy.max_bytes == 0 ||
            policy.cleanup_policy != path_cleanup_policy::remove) {
            return std::unexpected(
                std::string{"ephemeral write requires bounded removable materialization"}
            );
        }
        break;
    case path_access::retained_write:
        if (policy.materialization == path_materialization::bind || policy.max_bytes == 0 ||
            policy.cleanup_policy != path_cleanup_policy::retain) {
            return std::unexpected(
                std::string{"retained write requires bounded retained materialization"}
            );
        }
        break;
    case path_access::direct_write:
        if (policy.materialization != path_materialization::bind || policy.max_bytes != 0 ||
            policy.create_policy != path_create_policy::never ||
            policy.cleanup_policy != path_cleanup_policy::retain) {
            return std::unexpected(std::string{"direct write must be a retained existing bind"});
        }
        break;
    }
    return {};
}

auto selected_policy(const path_alias_policy& policy, path_access requested)
    -> const path_access_policy* {
    const auto found =
        std::find_if(policy.access.begin(), policy.access.end(), [&](const auto& mode) {
            return mode.access == requested;
        });
    return found == policy.access.end() ? nullptr : &*found;
}

auto validate_request_bounds(
    const path_alias_policy& policy,
    const path_access_policy& mode,
    const path_grant_request& request
) -> std::expected<void, std::string> {
    if (request.ttl_secs == 0 || request.ttl_secs > policy.max_ttl_secs) {
        return std::unexpected(std::string{"path grant TTL exceeds host policy"});
    }
    if (request.access == path_access::ephemeral_write ||
        request.access == path_access::retained_write) {
        if (request.max_bytes == 0 || request.max_bytes > mode.max_bytes) {
            return std::unexpected(std::string{"path grant quota exceeds host policy"});
        }
    } else if (request.max_bytes != 0) {
        return std::unexpected(
            std::string{"read or legacy direct-write grants may not request a write quota"}
        );
    }
    return {};
}

} // namespace

resolved_path_grant::resolved_path_grant(
    int descriptor_fd,
    std::string alias,
    std::string host_path,
    std::string target_path,
    const path_access_policy& policy,
    const path_grant_request& request,
    path_identity identity,
    std::uint64_t exposure_generation,
    std::string exposure_scope_digest,
    std::string source_identity_digest
)
    : descriptor_fd_{descriptor_fd},
      alias_{std::move(alias)},
      host_path_{std::move(host_path)},
      target_path_{std::move(target_path)},
      access_{policy.access},
      materialization_{policy.materialization},
      create_policy_{policy.create_policy},
      cleanup_policy_{policy.cleanup_policy},
      ttl_secs_{request.ttl_secs},
      max_bytes_{request.max_bytes},
      identity_{identity},
      exposure_generation_{exposure_generation},
      exposure_scope_digest_{std::move(exposure_scope_digest)},
      source_identity_digest_{std::move(source_identity_digest)} {}

resolved_path_grant::resolved_path_grant(resolved_path_grant&& other) noexcept
    : descriptor_fd_{std::exchange(other.descriptor_fd_, -1)},
      alias_{std::move(other.alias_)},
      host_path_{std::move(other.host_path_)},
      target_path_{std::move(other.target_path_)},
      access_{other.access_},
      materialization_{other.materialization_},
      create_policy_{other.create_policy_},
      cleanup_policy_{other.cleanup_policy_},
      ttl_secs_{other.ttl_secs_},
      max_bytes_{other.max_bytes_},
      identity_{other.identity_},
      exposure_generation_{other.exposure_generation_},
      exposure_scope_digest_{std::move(other.exposure_scope_digest_)},
      source_identity_digest_{std::move(other.source_identity_digest_)} {}

auto resolved_path_grant::operator=(resolved_path_grant&& other) noexcept -> resolved_path_grant& {
    if (this != &other) {
        close_descriptor();
        descriptor_fd_ = std::exchange(other.descriptor_fd_, -1);
        alias_ = std::move(other.alias_);
        host_path_ = std::move(other.host_path_);
        target_path_ = std::move(other.target_path_);
        access_ = other.access_;
        materialization_ = other.materialization_;
        create_policy_ = other.create_policy_;
        cleanup_policy_ = other.cleanup_policy_;
        ttl_secs_ = other.ttl_secs_;
        max_bytes_ = other.max_bytes_;
        identity_ = other.identity_;
        exposure_generation_ = other.exposure_generation_;
        exposure_scope_digest_ = std::move(other.exposure_scope_digest_);
        source_identity_digest_ = std::move(other.source_identity_digest_);
    }
    return *this;
}

resolved_path_grant::~resolved_path_grant() {
    close_descriptor();
}

void resolved_path_grant::close_descriptor() noexcept {
    if (descriptor_fd_ >= 0) {
        ::close(descriptor_fd_);
        descriptor_fd_ = -1;
    }
}

auto resolved_path_grant::verify_identity() const -> std::expected<void, std::string> {
    if (descriptor_fd_ < 0) {
        return std::unexpected(std::string{"path grant is closed"});
    }
    auto reopened = open_path_no_follow(host_path_, alias_);
    if (!reopened) {
        return std::unexpected(reopened.error());
    }
    auto current = identity_for(reopened->get(), alias_);
    if (!current) {
        return std::unexpected(current.error());
    }
    if (*current != identity_) {
        return std::unexpected(std::string{"path alias identity changed before launch"});
    }
    return {};
}

result<path_alias_registry> path_alias_registry::build(std::vector<path_alias_policy> policies) {
    path_alias_registry registry;
    for (auto& policy : policies) {
        if (!valid_alias(policy.alias)) {
            return std::unexpected(std::string{"invalid bounded path alias"});
        }
        if (!valid_absolute_path(policy.host_path) || reserved_host(policy.host_path)) {
            return std::unexpected(std::string{"path alias has invalid host path"});
        }
        if (!valid_absolute_path(policy.target_path) || reserved_target(policy.target_path)) {
            return std::unexpected(std::string{"path alias has invalid or reserved target path"});
        }
        if (policy.max_ttl_secs == 0 || policy.access.empty()) {
            return std::unexpected(std::string{"path alias requires TTL and access policy"});
        }
        std::set<path_access> seen_access;
        for (const auto& mode : policy.access) {
            if (!seen_access.insert(mode.access).second) {
                return std::unexpected(std::string{"path alias has duplicate access policy"});
            }
            if (auto checked = validate_access_policy(mode); !checked) {
                return std::unexpected(checked.error());
            }
        }
        auto source = open_path_no_follow(policy.host_path, policy.alias);
        if (!source) {
            return std::unexpected(source.error());
        }
        auto source_identity = identity_for(source->get(), policy.alias);
        if (!source_identity) {
            return std::unexpected(source_identity.error());
        }
        if (registry.policies_.contains(policy.alias)) {
            return std::unexpected(std::string{"duplicate path alias"});
        }
        const std::filesystem::path host_path{policy.host_path};
        const std::filesystem::path target_path{policy.target_path};
        for (const auto& [existing_alias, existing] : registry.policies_) {
            const std::filesystem::path existing_host{existing.host_path};
            const std::filesystem::path existing_target{existing.target_path};
            if (path_within(host_path, existing_host) || path_within(existing_host, host_path)) {
                return std::unexpected(std::string{"overlapping host path aliases"});
            }
            if (path_within(target_path, existing_target) ||
                path_within(existing_target, target_path)) {
                return std::unexpected(std::string{"overlapping sandbox target aliases"});
            }
            auto existing_source = open_path_no_follow(existing.host_path, existing_alias);
            if (!existing_source) {
                return std::unexpected(existing_source.error());
            }
            auto existing_identity = identity_for(existing_source->get(), existing_alias);
            if (!existing_identity) {
                return std::unexpected(existing_identity.error());
            }
            if (*existing_identity == *source_identity) {
                return std::unexpected(std::string{"path aliases reference the same host object"});
            }
        }
        auto alias = policy.alias;
        registry.policies_.emplace(std::move(alias), std::move(policy));
    }
    return registry;
}

result<resolved_path_grant> path_alias_registry::resolve(const path_grant_request& request) const {
    if (!valid_alias(request.alias)) {
        return std::unexpected(std::string{"invalid bounded path alias request"});
    }
    const auto policy_entry = policies_.find(request.alias);
    if (policy_entry == policies_.end()) {
        return std::unexpected(std::string{"unknown path alias"});
    }
    const auto& policy = policy_entry->second;
    const auto* mode = selected_policy(policy, request.access);
    if (mode == nullptr) {
        return std::unexpected(std::string{"requested path access is not allowed"});
    }
    if (request.access == path_access::direct_write) {
        return std::unexpected(std::string{"direct write requires authenticated local approval"});
    }
    if (auto bounds = validate_request_bounds(policy, *mode, request); !bounds) {
        return std::unexpected(bounds.error());
    }

    auto source = open_path_no_follow(policy.host_path, policy.alias);
    if (!source) {
        return std::unexpected(source.error());
    }
    auto identity = identity_for(source->get(), policy.alias);
    if (!identity) {
        return std::unexpected(identity.error());
    }
    return resolved_path_grant{
        source->release(),
        policy.alias,
        policy.host_path,
        policy.target_path,
        *mode,
        request,
        *identity,
    };
}

auto path_alias_registry::validate_plan(const path_grant_plan_request& request) const
    -> std::expected<void, std::string> {
    if (!valid_alias(request.grant.alias)) {
        return std::unexpected(std::string{"invalid bounded path alias request"});
    }
    const auto policy_entry = policies_.find(request.grant.alias);
    if (policy_entry == policies_.end()) {
        return std::unexpected(std::string{"unknown path alias"});
    }
    const auto& policy = policy_entry->second;
    const auto* mode = selected_policy(policy, request.grant.access);
    if (mode == nullptr) {
        return std::unexpected(std::string{"requested path access is not allowed"});
    }
    if (mode->materialization != request.materialization ||
        mode->cleanup_policy != request.cleanup_policy) {
        return std::unexpected(std::string{"path grant projection differs from host policy"});
    }
    if (auto bounds = validate_request_bounds(policy, *mode, request.grant); !bounds) {
        return std::unexpected(bounds.error());
    }
    auto source = open_path_no_follow(policy.host_path, policy.alias);
    if (!source) {
        return std::unexpected(source.error());
    }
    if (auto identity = identity_for(source->get(), policy.alias); !identity) {
        return std::unexpected(identity.error());
    }
    return {};
}

} // namespace glove::supervisor
