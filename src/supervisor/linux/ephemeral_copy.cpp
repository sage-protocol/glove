#include "glove/supervisor/linux_ephemeral_copy.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace glove::supervisor::linux_detail {

namespace {

constexpr std::uint64_t max_copy_entries = 100'000;
constexpr unsigned int max_copy_depth = 64;
constexpr std::size_t copy_buffer_bytes = std::size_t{64} * 1024U;
constexpr long tmpfs_magic = 0x01021994;
constexpr std::string_view regular_file_payload = ".glove-payload";

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

class unique_directory {
public:
    explicit unique_directory(::DIR* directory = nullptr) noexcept : directory_{directory} {}

    unique_directory(const unique_directory&) = delete;
    auto operator=(const unique_directory&) -> unique_directory& = delete;
    unique_directory(unique_directory&&) = delete;
    auto operator=(unique_directory&&) -> unique_directory& = delete;

    ~unique_directory() {
        if (directory_ != nullptr) {
            ::closedir(directory_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> ::DIR* { return directory_; }

private:
    ::DIR* directory_;
};

struct copy_state {
    std::uint64_t max_bytes = 0;
    std::uint64_t logical_bytes = 0;
    std::uint64_t regular_files = 0;
    std::uint64_t directories = 0;
    std::uint64_t entries = 0;
};

auto errno_message(int error) -> std::string {
    return std::error_code{error, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 64 && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' || character == '.';
    });
}

auto valid_recovery_directory_name(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 255U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' || character == '.';
    });
}

result<unique_fd> open_absolute_directory_no_follow(std::string_view raw) {
    const std::filesystem::path path{raw};
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"invalid materialization root"});
    }
    unique_fd current{::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC)};
    if (current.get() < 0) {
        return std::unexpected(std::string{"open materialization root: "} + errno_message(errno));
    }
    for (const auto& component : path.relative_path()) {
        const std::string name = component.string();
        unique_fd next{
            ::openat(current.get(), name.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (next.get() < 0) {
            return std::unexpected(
                std::string{"resolve materialization root: "} + errno_message(errno)
            );
        }
        current = std::move(next);
    }
    struct ::stat status = {};
    if (::fstat(current.get(), &status) < 0) {
        return std::unexpected(
            std::string{"inspect materialization root: "} + errno_message(errno)
        );
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != ::geteuid() || (status.st_mode & 0077U) != 0) {
        return std::unexpected(std::string{"materialization root must be an owner-only directory"});
    }
    return current;
}

auto mount_target_path(int root_fd, std::string_view directory_name) -> std::string {
    return "/proc/self/fd/" + std::to_string(root_fd) + "/" + std::string{directory_name};
}

// Owns the namespace side effects between mkdirat/move_mount and the
// materialization object's noexcept adoption. The caller allocates both
// strings before the first side effect, so rollback cannot allocate.
class pending_materialization {
public:
    pending_materialization(
        int root_fd, const char* directory_name, const char* mount_path
    ) noexcept
        : root_fd_{root_fd}, directory_name_{directory_name}, mount_path_{mount_path} {}

    pending_materialization(const pending_materialization&) = delete;
    auto operator=(const pending_materialization&) -> pending_materialization& = delete;
    pending_materialization(pending_materialization&&) = delete;
    auto operator=(pending_materialization&&) -> pending_materialization& = delete;

    ~pending_materialization() {
        if (mounted_) {
            static_cast<void>(::umount2(mount_path_, MNT_DETACH));
        }
        if (directory_created_) {
            static_cast<void>(::unlinkat(root_fd_, directory_name_, AT_REMOVEDIR));
        }
    }

    void mark_directory_created() noexcept { directory_created_ = true; }

    void mark_mounted() noexcept { mounted_ = true; }

    void release() noexcept {
        mounted_ = false;
        directory_created_ = false;
    }

private:
    int root_fd_;
    const char* directory_name_;
    const char* mount_path_;
    bool directory_created_ = false;
    bool mounted_ = false;
};

auto mount_unavailable(int error) -> bool {
    return error == EACCES || error == ENOSYS || error == EOPNOTSUPP || error == EPERM;
}

auto mount_quota_tmpfs(int target_fd, std::uint64_t max_bytes) -> result<void> {
    unique_fd context{static_cast<int>(::syscall(SYS_fsopen, "tmpfs", FSOPEN_CLOEXEC))};
    if (context.get() < 0) {
        const int saved = errno;
        const auto prefix = mount_unavailable(saved) ? "quota-backed tmpfs mount unavailable: "
                                                     : "open tmpfs mount context: ";
        return std::unexpected(std::string{prefix} + errno_message(saved));
    }
    const std::string size = std::to_string(max_bytes);
    if (::syscall(SYS_fsconfig, context.get(), FSCONFIG_SET_STRING, "size", size.c_str(), 0) < 0 ||
        ::syscall(SYS_fsconfig, context.get(), FSCONFIG_SET_STRING, "mode", "0700", 0) < 0 ||
        ::syscall(SYS_fsconfig, context.get(), FSCONFIG_CMD_CREATE, nullptr, nullptr, 0) < 0) {
        return std::unexpected(
            std::string{"configure quota-backed tmpfs: "} + errno_message(errno)
        );
    }
    unique_fd detached{static_cast<int>(::syscall(
        SYS_fsmount,
        context.get(),
        FSMOUNT_CLOEXEC,
        static_cast<unsigned int>(MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
    ))};
    if (detached.get() < 0) {
        return std::unexpected(std::string{"create quota-backed tmpfs: "} + errno_message(errno));
    }
    constexpr unsigned int move_flags = MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH;
    if (::syscall(SYS_move_mount, detached.get(), "", target_fd, "", move_flags) < 0) {
        return std::unexpected(std::string{"attach quota-backed tmpfs: "} + errno_message(errno));
    }
    return {};
}

auto stable_metadata(const struct ::stat& before, const struct ::stat& after) -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

auto require_exact_quota_granularity(std::uint64_t max_bytes) -> result<void> {
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return std::unexpected(std::string{"cannot determine filesystem quota granularity"});
    }
    const auto page_bytes = static_cast<std::uint64_t>(page_size);
    if (max_bytes < page_bytes || max_bytes % page_bytes != 0) {
        return std::unexpected(std::string{"materialization quota must be a page multiple"});
    }
    return {};
}

auto reserve_bytes(copy_state& state, std::size_t bytes) -> result<void> {
    const auto count = static_cast<std::uint64_t>(bytes);
    if (state.logical_bytes > state.max_bytes || count > state.max_bytes - state.logical_bytes) {
        return std::unexpected(std::string{"materialization quota exceeded while copying"});
    }
    state.logical_bytes += count;
    return {};
}

auto write_all(int fd, const char* data, std::size_t size) -> result<void> {
    std::size_t offset = 0;
    while (offset < size) {
        const ::ssize_t written = ::write(fd, data + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EDQUOT || errno == ENOSPC) {
                return std::unexpected(std::string{"materialization filesystem quota exceeded"});
            }
            return std::unexpected(std::string{"write materialized file: "} + errno_message(errno));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

auto copy_file_descriptor(int source_fd, int destination_fd, copy_state& state) -> result<void> {
    struct ::stat before = {};
    if (::fstat(source_fd, &before) < 0 || !S_ISREG(before.st_mode)) {
        return std::unexpected(std::string{"materialization source file changed type"});
    }
    if (before.st_nlink != 1) {
        return std::unexpected(std::string{"materialization source contains a hardlinked file"});
    }
    std::array<char, copy_buffer_bytes> buffer{};
    for (;;) {
        const ::ssize_t count = ::read(source_fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                std::string{"read materialization source: "} + errno_message(errno)
            );
        }
        if (count == 0) {
            break;
        }
        const auto size = static_cast<std::size_t>(count);
        if (auto reserved = reserve_bytes(state, size); !reserved) {
            return reserved;
        }
        if (auto written = write_all(destination_fd, buffer.data(), size); !written) {
            return written;
        }
    }
    struct ::stat after = {};
    if (::fstat(source_fd, &after) < 0 || !stable_metadata(before, after)) {
        return std::unexpected(std::string{"materialization source changed while copying"});
    }
    ++state.regular_files;
    return {};
}

auto open_pinned_source(int descriptor_fd, int flags) -> result<unique_fd> {
    const std::string path = "/proc/self/fd/" + std::to_string(descriptor_fd);
    unique_fd source{::open(path.c_str(), flags | O_CLOEXEC)};
    if (source.get() < 0) {
        return std::unexpected(
            std::string{"reopen pinned materialization source: "} + errno_message(errno)
        );
    }
    return source;
}

auto safe_file_mode(::mode_t source_mode) -> ::mode_t {
    return static_cast<::mode_t>((source_mode & 0555U) | 0600U);
}

auto safe_directory_mode(::mode_t source_mode) -> ::mode_t {
    return static_cast<::mode_t>((source_mode & 0555U) | 0700U);
}

auto copy_regular_entry(
    int source_parent,
    int destination_parent,
    const char* name,
    const struct ::stat& expected,
    copy_state& state
) -> result<void> {
    unique_fd source{::openat(source_parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (source.get() < 0) {
        return std::unexpected(
            std::string{"open materialization source file: "} + errno_message(errno)
        );
    }
    struct ::stat opened = {};
    if (::fstat(source.get(), &opened) < 0 || !S_ISREG(opened.st_mode) ||
        !stable_metadata(expected, opened)) {
        return std::unexpected(std::string{"materialization source entry changed before copy"});
    }
    if (opened.st_nlink != 1) {
        return std::unexpected(std::string{"materialization source contains a hardlinked file"});
    }
    unique_fd destination{::openat(
        destination_parent,
        name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        safe_file_mode(opened.st_mode)
    )};
    if (destination.get() < 0) {
        return std::unexpected(std::string{"create materialized file: "} + errno_message(errno));
    }
    if (::fchmod(destination.get(), safe_file_mode(opened.st_mode)) < 0) {
        return std::unexpected(std::string{"set materialized file mode: "} + errno_message(errno));
    }
    return copy_file_descriptor(source.get(), destination.get(), state);
}

auto copy_directory_contents(
    int source_fd, int destination_fd, copy_state& state, unsigned int depth
) -> result<void> {
    if (depth > max_copy_depth) {
        return std::unexpected(std::string{"materialization directory depth exceeds bound"});
    }
    struct ::stat before = {};
    if (::fstat(source_fd, &before) < 0 || !S_ISDIR(before.st_mode)) {
        return std::unexpected(std::string{"materialization source directory changed type"});
    }
    unique_fd iterator_fd{::fcntl(source_fd, F_DUPFD_CLOEXEC, 0)};
    if (iterator_fd.get() < 0) {
        return std::unexpected(
            std::string{"duplicate materialization directory: "} + errno_message(errno)
        );
    }
    ::DIR* raw_directory = ::fdopendir(iterator_fd.get());
    if (raw_directory == nullptr) {
        return std::unexpected(
            std::string{"iterate materialization directory: "} + errno_message(errno)
        );
    }
    static_cast<void>(iterator_fd.release());
    unique_directory directory{raw_directory};
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(
                    std::string{"read materialization directory entry: "} + errno_message(errno)
                );
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (++state.entries > max_copy_entries) {
            return std::unexpected(std::string{"materialization entry count exceeds bound"});
        }
        struct ::stat entry_status = {};
        if (::fstatat(source_fd, entry->d_name, &entry_status, AT_SYMLINK_NOFOLLOW) < 0) {
            return std::unexpected(
                std::string{"inspect materialization source entry: "} + errno_message(errno)
            );
        }
        if (S_ISREG(entry_status.st_mode)) {
            if (auto copied = copy_regular_entry(
                    source_fd, destination_fd, entry->d_name, entry_status, state
                );
                !copied) {
                return copied;
            }
            continue;
        }
        if (!S_ISDIR(entry_status.st_mode)) {
            return std::unexpected(
                std::string{"materialization source contains a symlink or special file"}
            );
        }
        unique_fd source_child{
            ::openat(source_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (source_child.get() < 0) {
            return std::unexpected(
                std::string{"open materialization source directory: "} + errno_message(errno)
            );
        }
        struct ::stat opened = {};
        if (::fstat(source_child.get(), &opened) < 0 || !stable_metadata(entry_status, opened)) {
            return std::unexpected(
                std::string{"materialization source directory changed before copy"}
            );
        }
        if (::mkdirat(destination_fd, entry->d_name, 0700) < 0) {
            return std::unexpected(
                std::string{"create materialized directory: "} + errno_message(errno)
            );
        }
        unique_fd destination_child{
            ::openat(destination_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (destination_child.get() < 0) {
            return std::unexpected(
                std::string{"open materialized directory: "} + errno_message(errno)
            );
        }
        ++state.directories;
        if (auto copied = copy_directory_contents(
                source_child.get(), destination_child.get(), state, depth + 1
            );
            !copied) {
            return copied;
        }
        if (::fchmod(destination_child.get(), safe_directory_mode(opened.st_mode)) < 0) {
            return std::unexpected(
                std::string{"set materialized directory mode: "} + errno_message(errno)
            );
        }
    }
    struct ::stat after = {};
    if (::fstat(source_fd, &after) < 0 || !stable_metadata(before, after)) {
        return std::unexpected(std::string{"materialization source changed while copying"});
    }
    return {};
}

struct filesystem_usage {
    std::uint64_t used_bytes = 0;
    std::uint64_t capacity_bytes = 0;
};

auto checked_filesystem_usage(int fd) -> result<filesystem_usage> {
    struct ::statfs status = {};
    if (::fstatfs(fd, &status) < 0) {
        return std::unexpected(
            std::string{"observe materialization filesystem: "} + errno_message(errno)
        );
    }
    if (status.f_type != tmpfs_magic || status.f_blocks < status.f_bfree || status.f_bsize <= 0) {
        return std::unexpected(std::string{"materialization filesystem identity is invalid"});
    }
    const auto blocks = static_cast<std::uint64_t>(status.f_blocks);
    const auto used_blocks = static_cast<std::uint64_t>(status.f_blocks - status.f_bfree);
    const auto block_size = static_cast<std::uint64_t>(status.f_bsize);
    if (blocks > std::numeric_limits<std::uint64_t>::max() / block_size) {
        return std::unexpected(std::string{"materialization usage exceeds receipt representation"});
    }
    return filesystem_usage{
        .used_bytes = used_blocks * block_size,
        .capacity_bytes = blocks * block_size,
    };
}

} // namespace

ephemeral_copy_materialization::ephemeral_copy_materialization(
    int root_fd,
    int mount_root_fd,
    std::string directory_name,
    std::string mount_path,
    std::string target_path,
    std::string alias,
    std::uint64_t quota_bytes,
    bool cleanup_on_destroy
) noexcept
    : root_fd_{root_fd},
      mount_root_fd_{mount_root_fd},
      directory_name_{std::move(directory_name)},
      mount_path_{std::move(mount_path)},
      target_path_{std::move(target_path)},
      alias_{std::move(alias)},
      quota_bytes_{quota_bytes},
      mounted_{true},
      cleanup_on_destroy_{cleanup_on_destroy} {}

ephemeral_copy_materialization::ephemeral_copy_materialization(
    ephemeral_copy_materialization&& other
) noexcept
    : root_fd_{std::exchange(other.root_fd_, -1)},
      mount_root_fd_{std::exchange(other.mount_root_fd_, -1)},
      content_fd_{std::exchange(other.content_fd_, -1)},
      directory_name_{std::move(other.directory_name_)},
      mount_path_{std::move(other.mount_path_)},
      target_path_{std::move(other.target_path_)},
      alias_{std::move(other.alias_)},
      quota_bytes_{other.quota_bytes_},
      logical_bytes_{other.logical_bytes_},
      regular_files_{other.regular_files_},
      directories_{other.directories_},
      source_identity_{other.source_identity_},
      is_directory_{other.is_directory_},
      mounted_{std::exchange(other.mounted_, false)},
      cleanup_on_destroy_{std::exchange(other.cleanup_on_destroy_, false)} {}

ephemeral_copy_materialization::~ephemeral_copy_materialization() {
    if (cleanup_on_destroy_) {
        cleanup_noexcept();
        return;
    }
    close_content_descriptors();
    close_root_descriptor();
}

result<ephemeral_copy_materialization> ephemeral_copy_materialization::create_mounted(
    std::string_view materialization_root,
    std::string directory_name,
    std::string target_path,
    std::string alias,
    std::uint64_t quota_bytes
) {
    if (auto granularity = require_exact_quota_granularity(quota_bytes); !granularity) {
        return std::unexpected(granularity.error());
    }
    auto root = open_absolute_directory_no_follow(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    std::string mount_path = mount_target_path(root->get(), directory_name);
    pending_materialization pending{root->get(), directory_name.c_str(), mount_path.c_str()};
    if (::mkdirat(root->get(), directory_name.c_str(), 0700) < 0) {
        return std::unexpected(
            std::string{"create materialization directory: "} + errno_message(errno)
        );
    }
    pending.mark_directory_created();
    unique_fd target{
        ::openat(root->get(), directory_name.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (target.get() < 0) {
        return std::unexpected(
            std::string{"open materialization directory: "} + errno_message(errno)
        );
    }
    if (auto mounted = mount_quota_tmpfs(target.get(), quota_bytes); !mounted) {
        return std::unexpected(mounted.error());
    }
    pending.mark_mounted();
    unique_fd mounted_root{::openat(
        root->get(), directory_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (mounted_root.get() < 0) {
        return std::unexpected(
            std::string{"open mounted materialization: "} + errno_message(errno)
        );
    }
    pending.release();
    ephemeral_copy_materialization materialization{
        root->release(),
        mounted_root.release(),
        std::move(directory_name),
        std::move(mount_path),
        std::move(target_path),
        std::move(alias),
        quota_bytes,
        true,
    };
    auto initial_filesystem = checked_filesystem_usage(materialization.mount_root_fd_);
    if (!initial_filesystem || initial_filesystem->capacity_bytes != quota_bytes) {
        return std::unexpected(
            initial_filesystem ? std::string{"materialization quota capacity mismatch"}
                               : initial_filesystem.error()
        );
    }
    return materialization;
}

result<std::optional<ephemeral_copy_materialization>>
ephemeral_copy_materialization::adopt_recovered(
    std::string_view materialization_root,
    std::string directory_name,
    std::string alias,
    std::uint64_t quota_bytes
) {
    if (!valid_recovery_directory_name(directory_name) || !valid_recovery_directory_name(alias)) {
        return std::unexpected(std::string{"invalid recovered materialization identity"});
    }
    if (auto granularity = require_exact_quota_granularity(quota_bytes); !granularity) {
        return std::unexpected(granularity.error());
    }
    auto root = open_absolute_directory_no_follow(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    unique_fd mounted_root{::openat(
        root->get(), directory_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (mounted_root.get() < 0) {
        if (errno == ENOENT) {
            return std::optional<ephemeral_copy_materialization>{};
        }
        return std::unexpected(
            std::string{"open recovered materialization: "} + errno_message(errno)
        );
    }
    auto filesystem = checked_filesystem_usage(mounted_root.get());
    if (!filesystem || filesystem->capacity_bytes != quota_bytes) {
        return std::unexpected(
            filesystem ? std::string{"recovered materialization quota mismatch"}
                       : filesystem.error()
        );
    }
    auto mount_path = mount_target_path(root->get(), directory_name);
    ephemeral_copy_materialization recovered{
        root->release(),
        mounted_root.release(),
        std::move(directory_name),
        std::move(mount_path),
        std::string{},
        std::move(alias),
        quota_bytes,
        false
    };
    return std::optional<ephemeral_copy_materialization>{std::move(recovered)};
}

result<ephemeral_copy_materialization> ephemeral_copy_materialization::create_empty_session_scratch(
    std::string_view materialization_root, std::string_view session_id, std::uint64_t quota_bytes
) {
    if (!valid_identifier(session_id)) {
        return std::unexpected(std::string{"invalid session filesystem identifier"});
    }
    std::string name =
        "glove-sessionfs-s" + std::to_string(session_id.size()) + "-" + std::string{session_id};
    auto materialization = create_mounted(
        materialization_root, std::move(name), std::string{}, "__scratch", quota_bytes
    );
    if (!materialization) {
        return std::unexpected(materialization.error());
    }
    for (const auto* directory : {"tmp", "var-tmp"}) {
        if (::mkdirat(materialization->mount_root_fd_, directory, 0700) < 0) {
            return std::unexpected(
                std::string{"create session scratch directory: "} + errno_message(errno)
            );
        }
    }
    materialization->content_fd_ = ::fcntl(materialization->mount_root_fd_, F_DUPFD_CLOEXEC, 0);
    if (materialization->content_fd_ < 0) {
        return std::unexpected(
            std::string{"duplicate session scratch descriptor: "} + errno_message(errno)
        );
    }
    materialization->directories_ = 3;
    materialization->is_directory_ = true;
    return materialization;
}

result<ephemeral_copy_materialization> ephemeral_copy_materialization::create(
    std::string_view materialization_root,
    std::string_view session_id,
    const resolved_path_grant& grant
) {
    if (!valid_identifier(session_id) || !valid_identifier(grant.alias())) {
        return std::unexpected(std::string{"invalid materialization identifier"});
    }
    if (grant.access() != path_access::ephemeral_write ||
        grant.materialization() != path_materialization::copy || grant.max_bytes() == 0 ||
        grant.cleanup_policy() != path_cleanup_policy::remove) {
        return std::unexpected(std::string{"grant is not an ephemeral copy materialization"});
    }
    if (auto identity = grant.verify_identity(); !identity) {
        return std::unexpected(identity.error());
    }
    std::string name = "glove-mat-s" + std::to_string(session_id.size()) + "-" +
                       std::string{session_id} + "-a" + std::to_string(grant.alias().size()) + "-" +
                       std::string{grant.alias()};
    auto mounted = create_mounted(
        materialization_root,
        std::move(name),
        std::string{grant.target_path()},
        std::string{grant.alias()},
        grant.max_bytes()
    );
    if (!mounted) {
        return std::unexpected(mounted.error());
    }
    auto materialization = std::move(*mounted);

    struct ::stat source_status = {};
    if (::fstat(grant.descriptor_fd(), &source_status) < 0) {
        return std::unexpected(
            std::string{"inspect pinned materialization source: "} + errno_message(errno)
        );
    }
    copy_state state{.max_bytes = grant.max_bytes()};
    if (S_ISDIR(source_status.st_mode)) {
        auto source = open_pinned_source(grant.descriptor_fd(), O_RDONLY | O_DIRECTORY);
        if (!source) {
            return std::unexpected(source.error());
        }
        state.directories = 1;
        if (auto copied =
                copy_directory_contents(source->get(), materialization.mount_root_fd_, state, 0);
            !copied) {
            return std::unexpected(copied.error());
        }
        materialization.content_fd_ = ::fcntl(materialization.mount_root_fd_, F_DUPFD_CLOEXEC, 0);
        materialization.is_directory_ = true;
    } else if (S_ISREG(source_status.st_mode)) {
        auto source = open_pinned_source(grant.descriptor_fd(), O_RDONLY);
        if (!source) {
            return std::unexpected(source.error());
        }
        unique_fd destination{::openat(
            materialization.mount_root_fd_,
            regular_file_payload.data(),
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            safe_file_mode(source_status.st_mode)
        )};
        if (destination.get() < 0) {
            return std::unexpected(
                std::string{"create materialized payload: "} + errno_message(errno)
            );
        }
        if (auto copied = copy_file_descriptor(source->get(), destination.get(), state); !copied) {
            return std::unexpected(copied.error());
        }
        if (::lseek(destination.get(), 0, SEEK_SET) < 0) {
            return std::unexpected(
                std::string{"rewind materialized payload: "} + errno_message(errno)
            );
        }
        materialization.content_fd_ = destination.release();
        materialization.is_directory_ = false;
    } else {
        return std::unexpected(std::string{"materialization source changed type"});
    }
    if (materialization.content_fd_ < 0) {
        return std::unexpected(std::string{"duplicate materialized content descriptor failed"});
    }
    if (auto identity = grant.verify_identity(); !identity) {
        return std::unexpected(identity.error());
    }
    materialization.logical_bytes_ = state.logical_bytes;
    materialization.regular_files_ = state.regular_files;
    materialization.directories_ = state.directories;
    materialization.source_identity_ = grant.identity();
    if (auto usage = materialization.observe(); !usage) {
        return std::unexpected(usage.error());
    }
    return materialization;
}

result<materialization_usage> ephemeral_copy_materialization::observe() const {
    if (!mounted_ || mount_root_fd_ < 0) {
        return std::unexpected(std::string{"materialization is not mounted"});
    }
    auto filesystem = checked_filesystem_usage(mount_root_fd_);
    if (!filesystem) {
        return std::unexpected(filesystem.error());
    }
    if (filesystem->capacity_bytes != quota_bytes_) {
        return std::unexpected(std::string{"materialization quota capacity changed"});
    }
    return materialization_usage{
        .logical_bytes = logical_bytes_,
        .filesystem_bytes = filesystem->used_bytes,
        .quota_bytes = quota_bytes_,
        .regular_files = regular_files_,
        .directories = directories_,
    };
}

void ephemeral_copy_materialization::close_content_descriptors() noexcept {
    if (content_fd_ >= 0) {
        ::close(content_fd_);
        content_fd_ = -1;
    }
    if (mount_root_fd_ >= 0) {
        ::close(mount_root_fd_);
        mount_root_fd_ = -1;
    }
}

void ephemeral_copy_materialization::close_root_descriptor() noexcept {
    if (root_fd_ >= 0) {
        ::close(root_fd_);
        root_fd_ = -1;
    }
}

void ephemeral_copy_materialization::cleanup_noexcept() noexcept {
    close_content_descriptors();
    if (root_fd_ >= 0 && !directory_name_.empty()) {
        if (mounted_) {
            static_cast<void>(::umount2(mount_path_.c_str(), MNT_DETACH));
            mounted_ = false;
        }
        static_cast<void>(::unlinkat(root_fd_, directory_name_.c_str(), AT_REMOVEDIR));
    }
    directory_name_.clear();
    mount_path_.clear();
    close_root_descriptor();
}

result<void> ephemeral_copy_materialization::cleanup() {
    close_content_descriptors();
    if (root_fd_ < 0 || directory_name_.empty()) {
        return {};
    }
    if (mounted_) {
        if (::umount2(mount_path_.c_str(), 0) < 0) {
            return std::unexpected(std::string{"unmount materialization: "} + errno_message(errno));
        }
        mounted_ = false;
    }
    if (::unlinkat(root_fd_, directory_name_.c_str(), AT_REMOVEDIR) < 0) {
        return std::unexpected(
            std::string{"remove materialization directory: "} + errno_message(errno)
        );
    }
    directory_name_.clear();
    mount_path_.clear();
    close_root_descriptor();
    return {};
}

} // namespace glove::supervisor::linux_detail
