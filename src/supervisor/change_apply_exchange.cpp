#include "glove/supervisor/change_apply_exchange.hpp"

#include "glove/supervisor/change_apply_recovery.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#    include <dirent.h>
#    include <linux/fs.h>
#    include <sys/statvfs.h>
#    include <sys/syscall.h>
#    include <sys/xattr.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::supervisor {

namespace {

#if defined(__linux__)

constexpr unsigned int max_copy_depth = 64U;
constexpr std::size_t max_copy_entries = 100'000U;

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

class unique_directory {
public:
    explicit unique_directory(DIR* directory) noexcept : directory_{directory} {}

    unique_directory(const unique_directory&) = delete;
    auto operator=(const unique_directory&) -> unique_directory& = delete;
    unique_directory(unique_directory&&) = delete;
    auto operator=(unique_directory&&) -> unique_directory& = delete;

    ~unique_directory() {
        if (directory_ != nullptr) {
            (void)::closedir(directory_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> DIR* { return directory_; }

private:
    DIR* directory_ = nullptr;
};

struct copy_state {
    std::uint64_t max_bytes = 0;
    std::uint64_t bytes = 0;
    std::size_t entries = 0;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_component(std::string_view value) -> bool {
    return !value.empty() && value != "." && value != ".." && value.size() <= 255U &&
           value.find('/') == std::string_view::npos && value.find('\0') == std::string_view::npos;
}

auto stable_regular_metadata(const struct stat& before, const struct stat& after) -> bool {
    return S_ISREG(after.st_mode) && before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
           before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

auto stable_directory_metadata(const struct stat& before, const struct stat& after) -> bool {
    return S_ISDIR(after.st_mode) && before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
           before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

auto checked_add(std::uint64_t& total, std::uint64_t value, std::uint64_t maximum) -> bool {
    if (total > maximum || value > maximum - total) {
        return false;
    }
    total += value;
    return true;
}

auto validate_supported_metadata(int descriptor, const struct stat& status) -> result<void> {
    if (status.st_uid != ::geteuid() || status.st_gid != ::getegid() ||
        (status.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        return std::unexpected(
            std::string{"change apply tree ownership or special mode is unsupported"}
        );
    }
    errno = 0;
    const auto extended_bytes = ::flistxattr(descriptor, nullptr, 0);
    if (extended_bytes < 0) {
        return std::unexpected(error_message("inspect change apply extended metadata"));
    }
    if (extended_bytes != 0) {
        return std::unexpected(std::string{"change apply tree extended metadata is unsupported"});
    }
    if (S_ISREG(status.st_mode)) {
        if (status.st_nlink != 1 || status.st_size < 0 || status.st_blocks < 0) {
            return std::unexpected(
                std::string{"change apply tree regular-file metadata is unsupported"}
            );
        }
        const auto bytes = static_cast<std::uint64_t>(status.st_size);
        const auto required_blocks = bytes / 512U + (bytes % 512U == 0 ? 0U : 1U);
        if (static_cast<std::uint64_t>(status.st_blocks) < required_blocks) {
            return std::unexpected(std::string{"change apply sparse files are unsupported"});
        }
    } else if (!S_ISDIR(status.st_mode)) {
        return std::unexpected(std::string{"change apply tree type is unsupported"});
    }
    return {};
}

auto validate_tree_metadata(int descriptor, std::size_t& entries, unsigned int depth)
    -> result<void> {
    if (depth > max_copy_depth || entries >= max_copy_entries) {
        return std::unexpected(std::string{"change apply metadata bound exceeded"});
    }
    ++entries;
    struct stat before{};
    if (::fstat(descriptor, &before) != 0) {
        return std::unexpected(error_message("inspect change apply tree metadata"));
    }
    if (auto supported = validate_supported_metadata(descriptor, before); !supported) {
        return supported;
    }
    if (S_ISREG(before.st_mode)) {
        return {};
    }

    unique_fd iterator{::openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (iterator.get() < 0) {
        return std::unexpected(error_message("duplicate change apply metadata directory"));
    }
    DIR* raw = ::fdopendir(iterator.get());
    if (raw == nullptr) {
        return std::unexpected(error_message("iterate change apply metadata directory"));
    }
    (void)iterator.release();
    unique_directory directory{raw};
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(error_message("read change apply metadata directory"));
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (!valid_component(name) || entries >= max_copy_entries) {
            return std::unexpected(std::string{"change apply metadata entry bound exceeded"});
        }
        struct stat status{};
        if (::fstatat(descriptor, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(error_message("inspect change apply metadata entry"));
        }
        const std::string component{name};
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
        if (S_ISDIR(status.st_mode)) {
            flags |= O_DIRECTORY;
        } else if (!S_ISREG(status.st_mode)) {
            return std::unexpected(std::string{"change apply metadata type is unsupported"});
        }
        unique_fd child{::openat(descriptor, component.c_str(), flags)};
        if (child.get() < 0) {
            return std::unexpected(error_message("open change apply metadata entry"));
        }
        struct stat opened{};
        if (::fstat(child.get(), &opened) != 0 || opened.st_dev != status.st_dev ||
            opened.st_ino != status.st_ino || opened.st_mode != status.st_mode ||
            opened.st_uid != status.st_uid || opened.st_gid != status.st_gid) {
            return std::unexpected(std::string{"change apply metadata entry changed"});
        }
        if (auto valid = validate_tree_metadata(child.get(), entries, depth + 1U); !valid) {
            return valid;
        }
    }
    struct stat after{};
    if (::fstat(descriptor, &after) != 0 || !stable_directory_metadata(before, after)) {
        return std::unexpected(std::string{"change apply metadata tree changed"});
    }
    return {};
}

auto validate_parent_metadata(int descriptor) -> result<void> {
    struct stat status{};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != ::geteuid() || status.st_gid != ::getegid() ||
        (status.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        return std::unexpected(
            std::string{"change apply parent is outside the dedicated service-identity boundary"}
        );
    }
    return {};
}

auto write_all(int descriptor, const char* bytes, std::size_t size) -> result<void> {
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = ::write(descriptor, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(error_message("write change apply candidate"));
        }
        offset += static_cast<std::size_t>(count);
    }
    return {};
}

auto copy_regular_contents(
    int source, int destination, const struct stat& before, copy_state& state
) -> result<void> {
    if (!S_ISREG(before.st_mode) || before.st_nlink != 1 || before.st_size < 0) {
        return std::unexpected(std::string{"change apply stage contains an invalid regular file"});
    }
    const auto bytes = static_cast<std::uint64_t>(before.st_size);
    if (bytes > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
        !checked_add(state.bytes, bytes, state.max_bytes)) {
        return std::unexpected(std::string{"change apply candidate byte bound exceeded"});
    }
    std::array<char, std::size_t{64} * 1024U> buffer{};
    std::uint64_t consumed = 0;
    while (consumed < bytes) {
        const auto remaining = bytes - consumed;
        const auto requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size()))
        );
        const auto count = ::pread(source, buffer.data(), requested, static_cast<off_t>(consumed));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(error_message("read change apply stage"));
        }
        if (auto written = write_all(destination, buffer.data(), static_cast<std::size_t>(count));
            !written) {
            return written;
        }
        consumed += static_cast<std::uint64_t>(count);
    }
    struct stat after{};
    if (::fstat(source, &after) != 0 || !stable_regular_metadata(before, after)) {
        return std::unexpected(std::string{"change apply stage changed while copying"});
    }
    if (::fchown(destination, ::geteuid(), ::getegid()) != 0 ||
        ::fchmod(destination, before.st_mode & 0777U) != 0 || ::fsync(destination) != 0) {
        return std::unexpected(error_message("sync change apply candidate file"));
    }
    return {};
}

auto copy_regular_entry(
    int source_parent,
    int destination_parent,
    std::string_view name,
    const struct stat& before,
    copy_state& state
) -> result<void> {
    const std::string component{name};
    unique_fd source{::openat(source_parent, component.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (source.get() < 0) {
        return std::unexpected(error_message("open change apply stage file"));
    }
    struct stat opened{};
    if (::fstat(source.get(), &opened) != 0 || !stable_regular_metadata(before, opened)) {
        return std::unexpected(std::string{"change apply stage file changed before copying"});
    }
    unique_fd destination{::openat(
        destination_parent,
        component.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    )};
    if (destination.get() < 0) {
        return std::unexpected(error_message("create change apply candidate file"));
    }
    return copy_regular_contents(source.get(), destination.get(), opened, state);
}

auto copy_directory_contents(int source, int destination, copy_state& state, unsigned int depth)
    -> result<void> {
    if (depth > max_copy_depth) {
        return std::unexpected(std::string{"change apply candidate depth bound exceeded"});
    }
    struct stat before{};
    if (::fstat(source, &before) != 0 || !S_ISDIR(before.st_mode)) {
        return std::unexpected(std::string{"change apply stage directory is invalid"});
    }
    unique_fd iterator{::openat(source, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (iterator.get() < 0) {
        return std::unexpected(error_message("duplicate change apply stage directory"));
    }
    DIR* raw = ::fdopendir(iterator.get());
    if (raw == nullptr) {
        return std::unexpected(error_message("iterate change apply stage directory"));
    }
    (void)iterator.release();
    unique_directory directory{raw};
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(error_message("read change apply stage directory"));
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (!valid_component(name) || state.entries >= max_copy_entries) {
            return std::unexpected(std::string{"change apply candidate entry bound exceeded"});
        }
        ++state.entries;
        struct stat status{};
        if (::fstatat(source, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(error_message("inspect change apply stage entry"));
        }
        if (S_ISREG(status.st_mode)) {
            if (auto copied = copy_regular_entry(source, destination, name, status, state);
                !copied) {
                return copied;
            }
            continue;
        }
        if (!S_ISDIR(status.st_mode)) {
            return std::unexpected(
                std::string{"change apply stage contains a symlink or special file"}
            );
        }
        const std::string component{name};
        unique_fd source_child{
            ::openat(source, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (source_child.get() < 0) {
            return std::unexpected(error_message("open change apply stage directory"));
        }
        struct stat opened{};
        if (::fstat(source_child.get(), &opened) != 0 ||
            !stable_directory_metadata(status, opened)) {
            return std::unexpected(std::string{"change apply stage directory changed before copy"});
        }
        if (::mkdirat(destination, component.c_str(), 0700) != 0) {
            return std::unexpected(error_message("create change apply candidate directory"));
        }
        unique_fd destination_child{::openat(
            destination, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )};
        if (destination_child.get() < 0) {
            return std::unexpected(error_message("open change apply candidate directory"));
        }
        if (auto copied = copy_directory_contents(
                source_child.get(), destination_child.get(), state, depth + 1U
            );
            !copied) {
            return copied;
        }
        if (::fchown(destination_child.get(), ::geteuid(), ::getegid()) != 0 ||
            ::fchmod(destination_child.get(), opened.st_mode & 0777U) != 0) {
            return std::unexpected(error_message("set change apply candidate directory mode"));
        }
        if (::fsync(destination_child.get()) != 0) {
            return std::unexpected(error_message("sync change apply candidate directory mode"));
        }
    }
    struct stat after{};
    if (::fstat(source, &after) != 0 || !stable_directory_metadata(before, after)) {
        return std::unexpected(std::string{"change apply stage directory changed while copying"});
    }
    if (::fsync(destination) != 0) {
        return std::unexpected(error_message("sync change apply candidate directory"));
    }
    return {};
}

auto remove_directory_contents(int descriptor, unsigned int depth) -> result<void> {
    if (depth > max_copy_depth) {
        return std::unexpected(std::string{"change apply candidate cleanup depth exceeded"});
    }
    unique_fd iterator{::openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (iterator.get() < 0) {
        return std::unexpected(error_message("duplicate change apply candidate cleanup directory"));
    }
    DIR* raw = ::fdopendir(iterator.get());
    if (raw == nullptr) {
        return std::unexpected(error_message("iterate change apply candidate cleanup"));
    }
    (void)iterator.release();
    unique_directory directory{raw};
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(error_message("read change apply candidate cleanup"));
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (!valid_component(name)) {
            return std::unexpected(std::string{"change apply candidate cleanup name is invalid"});
        }
        struct stat status{};
        if (::fstatat(descriptor, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(error_message("inspect change apply candidate cleanup entry"));
        }
        if (S_ISDIR(status.st_mode)) {
            const std::string component{name};
            unique_fd child{::openat(
                descriptor, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )};
            if (child.get() < 0) {
                return std::unexpected(
                    error_message("open change apply candidate cleanup directory")
                );
            }
            if (auto removed = remove_directory_contents(child.get(), depth + 1U); !removed) {
                return removed;
            }
            if (::unlinkat(descriptor, component.c_str(), AT_REMOVEDIR) != 0) {
                return std::unexpected(error_message("remove change apply candidate directory"));
            }
        } else if (S_ISREG(status.st_mode)) {
            if (::unlinkat(descriptor, entry->d_name, 0) != 0) {
                return std::unexpected(error_message("remove change apply candidate file"));
            }
        } else {
            return std::unexpected(
                std::string{"change apply candidate cleanup encountered an unsupported type"}
            );
        }
    }
    return {};
}

class pending_candidate {
public:
    pending_candidate(int parent, std::string name, bool directory)
        : parent_{parent}, name_{std::move(name)}, directory_{directory} {}

    pending_candidate(const pending_candidate&) = delete;
    auto operator=(const pending_candidate&) -> pending_candidate& = delete;
    pending_candidate(pending_candidate&&) = delete;
    auto operator=(pending_candidate&&) -> pending_candidate& = delete;

    ~pending_candidate() noexcept {
        try {
            cleanup();
        } catch (...) {
            // Best-effort rollback must not mask the primary failure. A
            // deterministic leftover is discovered by recovery on restart.
        }
    }

    void release() noexcept { armed_ = false; }

private:
    void cleanup() {
        if (!armed_) {
            return;
        }
        if (directory_) {
            unique_fd candidate{
                ::openat(parent_, name_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            };
            if (candidate.get() >= 0) {
                (void)remove_directory_contents(candidate.get(), 0);
            }
            (void)::unlinkat(parent_, name_.c_str(), AT_REMOVEDIR);
        } else {
            (void)::unlinkat(parent_, name_.c_str(), 0);
        }
        (void)::fsync(parent_);
    }

    int parent_ = -1;
    std::string name_;
    bool directory_ = false;
    bool armed_ = true;
};

auto open_tree(int parent, std::string_view name, bool directory) -> result<unique_fd> {
    const std::string component{name};
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    if (directory) {
        flags |= O_DIRECTORY;
    }
    unique_fd descriptor{::openat(parent, component.c_str(), flags)};
    if (descriptor.get() < 0) {
        return std::unexpected(error_message("open change apply tree"));
    }
    struct stat status{};
    if (::fstat(descriptor.get(), &status) != 0 ||
        (directory ? !S_ISDIR(status.st_mode) : !S_ISREG(status.st_mode))) {
        return std::unexpected(std::string{"change apply tree type mismatch"});
    }
    return descriptor;
}

auto tree_digest(int descriptor, std::uint64_t max_bytes, std::uint64_t* logical_bytes = nullptr)
    -> result<std::string> {
    auto snapshot = snapshot_path_tree(descriptor, max_bytes);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (logical_bytes != nullptr) {
        std::uint64_t total = 0;
        for (const auto& entry : *snapshot) {
            if (entry.bytes > max_bytes - total) {
                return std::unexpected(std::string{"change apply tree byte total overflow"});
            }
            total += entry.bytes;
        }
        *logical_bytes = total;
    }
    return path_snapshot_digest(*snapshot);
}

auto validate_host_space(int parent, std::uint64_t candidate_bytes) -> result<void> {
    struct statvfs filesystem{};
    if (::fstatvfs(parent, &filesystem) != 0) {
        return std::unexpected(error_message("inspect change apply host space"));
    }
    const auto fragment = static_cast<std::uint64_t>(
        filesystem.f_frsize != 0 ? filesystem.f_frsize : filesystem.f_bsize
    );
    const auto blocks = static_cast<std::uint64_t>(filesystem.f_bavail);
    if (fragment == 0) {
        return std::unexpected(std::string{"change apply host space geometry is invalid"});
    }
    const auto available = blocks > std::numeric_limits<std::uint64_t>::max() / fragment
                               ? std::numeric_limits<std::uint64_t>::max()
                               : blocks * fragment;
    if (!change_apply_host_space_eligible(available, candidate_bytes)) {
        return std::unexpected(std::string{"change apply host space reserve is insufficient"});
    }
    return {};
}

auto validate_bindings(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<void> {
    auto decoded = decode_retained_change_manifest_json(manifest.canonical_json);
    if (!decoded || *decoded != manifest ||
        reservation.manifest_digest != manifest.manifest_digest ||
        reservation.session_id != manifest.session_id ||
        reservation.exposure_id != manifest.exposure_id ||
        reservation.generation != manifest.generation ||
        reservation.scope_digest != manifest.scope_digest ||
        reservation.source_identity_digest != manifest.source_identity_digest ||
        reservation.baseline_tree_digest != manifest.baseline_tree_digest ||
        reservation.staged_tree_digest != manifest.staged_tree_digest ||
        target.source_identity_digest() != reservation.source_identity_digest ||
        target.parent_descriptor_fd() < 0 || !valid_component(target.basename())) {
        return std::unexpected(std::string{"change apply exchange binding mismatch"});
    }
    return {};
}

#endif

} // namespace

auto change_apply_host_space_eligible(
    std::uint64_t available_bytes, std::uint64_t candidate_bytes, std::uint64_t reserve_bytes
) noexcept -> bool {
    return candidate_bytes <= std::numeric_limits<std::uint64_t>::max() - reserve_bytes &&
           available_bytes >= candidate_bytes + reserve_bytes;
}

auto validate_change_apply_exchange_preconditions(
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    int staged_descriptor
) -> result<void> {
#if !defined(__linux__)
    (void)manifest;
    (void)target;
    (void)staged_descriptor;
    return std::unexpected(std::string{"change apply exchange is unsupported on this platform"});
#else
    if (staged_descriptor < 0 || target.parent_descriptor_fd() < 0 ||
        !valid_component(target.basename())) {
        return std::unexpected(std::string{"change apply precondition descriptor is invalid"});
    }
    auto decoded = decode_retained_change_manifest_json(manifest.canonical_json);
    if (!decoded || *decoded != manifest ||
        target.source_identity_digest() != manifest.source_identity_digest) {
        return std::unexpected(std::string{"change apply precondition binding mismatch"});
    }
    if (auto parent = validate_parent_metadata(target.parent_descriptor_fd()); !parent) {
        return parent;
    }
    auto current_identity = target.current_source_identity_digest();
    if (!current_identity || *current_identity != manifest.source_identity_digest) {
        return std::unexpected(
            current_identity ? std::string{"change apply source identity changed"}
                             : current_identity.error()
        );
    }
    auto source = open_tree(target.parent_descriptor_fd(), target.basename(), manifest.directory);
    if (!source) {
        return std::unexpected(source.error());
    }
    struct stat stage_status{};
    if (::fstat(staged_descriptor, &stage_status) != 0 ||
        (manifest.directory ? !S_ISDIR(stage_status.st_mode) : !S_ISREG(stage_status.st_mode))) {
        return std::unexpected(std::string{"change apply stage type mismatch"});
    }
    std::size_t source_entries = 0;
    std::size_t stage_entries = 0;
    if (auto valid = validate_tree_metadata(source->get(), source_entries, 0); !valid) {
        return valid;
    }
    if (auto valid = validate_tree_metadata(staged_descriptor, stage_entries, 0); !valid) {
        return valid;
    }
    auto baseline = tree_digest(source->get(), manifest.max_bytes);
    std::uint64_t staged_bytes = 0;
    auto staged = tree_digest(staged_descriptor, manifest.max_bytes, &staged_bytes);
    if (!baseline || *baseline != manifest.baseline_tree_digest || !staged ||
        *staged != manifest.staged_tree_digest) {
        return std::unexpected(
            !baseline ? baseline.error()
            : !staged ? staged.error()
                      : std::string{"change apply precondition tree digest mismatch"}
        );
    }
    if (auto space = validate_host_space(target.parent_descriptor_fd(), staged_bytes); !space) {
        return space;
    }
    return {};
#endif
}

auto execute_change_apply_exchange(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target,
    int staged_descriptor
) -> result<change_apply_exchange_result> {
#if !defined(__linux__)
    (void)reservation;
    (void)manifest;
    (void)target;
    (void)staged_descriptor;
    return std::unexpected(std::string{"change apply exchange is unsupported on this platform"});
#else
    if (staged_descriptor < 0) {
        return std::unexpected(std::string{"change apply stage descriptor is invalid"});
    }
    if (auto valid = validate_bindings(reservation, manifest, target); !valid) {
        return std::unexpected(valid.error());
    }
    if (auto valid =
            validate_change_apply_exchange_preconditions(manifest, target, staged_descriptor);
        !valid) {
        return std::unexpected(valid.error());
    }
    auto candidate_name = change_apply_candidate_name(reservation.authorization_digest);
    if (!candidate_name) {
        return std::unexpected(candidate_name.error());
    }
    const int parent = target.parent_descriptor_fd();
    struct stat collision{};
    if (::fstatat(parent, candidate_name->c_str(), &collision, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        return std::unexpected(std::string{"change apply candidate already exists"});
    }

    auto initial_identity = target.current_source_identity_digest();
    if (!initial_identity || *initial_identity != reservation.source_identity_digest) {
        return std::unexpected(
            initial_identity ? std::string{"change apply source identity changed"}
                             : initial_identity.error()
        );
    }
    auto source = open_tree(parent, target.basename(), manifest.directory);
    if (!source) {
        return std::unexpected(source.error());
    }
    auto staged = tree_digest(staged_descriptor, manifest.max_bytes);
    if (!staged || *staged != reservation.staged_tree_digest) {
        return std::unexpected(
            staged ? std::string{"change apply stage digest changed"} : staged.error()
        );
    }

    unique_fd candidate;
    pending_candidate cleanup{parent, *candidate_name, manifest.directory};
    copy_state state{.max_bytes = manifest.max_bytes};
    if (manifest.directory) {
        struct stat stage_status{};
        struct stat source_status{};
        if (::fstat(staged_descriptor, &stage_status) != 0 || !S_ISDIR(stage_status.st_mode) ||
            ::fstat(source->get(), &source_status) != 0 || !S_ISDIR(source_status.st_mode) ||
            ::mkdirat(parent, candidate_name->c_str(), 0700) != 0) {
            return std::unexpected(error_message("create change apply candidate"));
        }
        candidate = unique_fd{::openat(
            parent, candidate_name->c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )};
        if (candidate.get() < 0) {
            return std::unexpected(error_message("open change apply candidate"));
        }
        if (auto copied = copy_directory_contents(staged_descriptor, candidate.get(), state, 0);
            !copied) {
            return std::unexpected(copied.error());
        }
        if (::fchown(candidate.get(), ::geteuid(), ::getegid()) != 0 ||
            ::fchmod(candidate.get(), source_status.st_mode & 0777U) != 0) {
            return std::unexpected(error_message("set change apply candidate root mode"));
        }
        if (::fsync(candidate.get()) != 0) {
            return std::unexpected(error_message("sync change apply candidate root mode"));
        }
    } else {
        struct stat stage_status{};
        if (::fstat(staged_descriptor, &stage_status) != 0 || !S_ISREG(stage_status.st_mode)) {
            return std::unexpected(std::string{"change apply stage type mismatch"});
        }
        candidate = unique_fd{::openat(
            parent,
            candidate_name->c_str(),
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600
        )};
        if (candidate.get() < 0) {
            return std::unexpected(error_message("create change apply candidate"));
        }
        if (auto copied =
                copy_regular_contents(staged_descriptor, candidate.get(), stage_status, state);
            !copied) {
            return std::unexpected(copied.error());
        }
    }
    if (::fsync(parent) != 0) {
        return std::unexpected(error_message("sync prepared change apply candidate"));
    }
    auto candidate_digest = tree_digest(candidate.get(), manifest.max_bytes);
    if (!candidate_digest || *candidate_digest != reservation.staged_tree_digest) {
        return std::unexpected(
            candidate_digest
                ? std::string{"change apply candidate digest mismatch: expected "} +
                      reservation.staged_tree_digest + " but found " + *candidate_digest
                : candidate_digest.error()
        );
    }
    auto baseline = tree_digest(source->get(), manifest.max_bytes);
    auto final_preexchange_identity = target.current_source_identity_digest();
    if (!baseline || *baseline != reservation.baseline_tree_digest || !final_preexchange_identity ||
        *final_preexchange_identity != reservation.source_identity_digest) {
        return std::unexpected(
            !baseline ? baseline.error()
                      : std::string{"change apply source changed before exchange"}
        );
    }

    const std::string source_name{target.basename()};
    const auto exchanged = static_cast<int>(::syscall(
        SYS_renameat2, parent, source_name.c_str(), parent, candidate_name->c_str(), RENAME_EXCHANGE
    ));
    if (exchanged != 0) {
        return std::unexpected(error_message("exchange change apply candidate"));
    }
    cleanup.release();
    if (::fsync(parent) != 0) {
        return std::unexpected(error_message("sync committed change apply exchange"));
    }

    auto installed = open_tree(parent, target.basename(), manifest.directory);
    auto prior = open_tree(parent, *candidate_name, manifest.directory);
    if (!installed || !prior) {
        return std::unexpected(!installed ? installed.error() : prior.error());
    }
    auto installed_digest = tree_digest(installed->get(), manifest.max_bytes);
    auto prior_digest = tree_digest(prior->get(), manifest.max_bytes);
    auto final_identity = target.current_source_identity_digest();
    if (!installed_digest || *installed_digest != reservation.staged_tree_digest || !prior_digest ||
        *prior_digest != reservation.baseline_tree_digest || !final_identity) {
        return std::unexpected(std::string{"change apply exchange requires recovery"});
    }
    return change_apply_exchange_result{
        .candidate_name = std::move(*candidate_name),
        .final_source_identity_digest = std::move(*final_identity),
        .final_tree_digest = std::move(*installed_digest),
    };
#endif
}

auto inspect_change_apply_exchange_recovery(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<change_apply_recovery_observation> {
#if !defined(__linux__)
    (void)reservation;
    (void)manifest;
    (void)target;
    return std::unexpected(std::string{"change apply recovery is unsupported on this platform"});
#else
    if (auto valid = validate_bindings(reservation, manifest, target); !valid) {
        return std::unexpected(valid.error());
    }
    auto candidate_name = change_apply_candidate_name(reservation.authorization_digest);
    if (!candidate_name) {
        return std::unexpected(candidate_name.error());
    }
    auto source = open_tree(target.parent_descriptor_fd(), target.basename(), manifest.directory);
    if (!source) {
        return std::unexpected(source.error());
    }
    auto source_digest = tree_digest(source->get(), manifest.max_bytes);
    auto source_identity = target.current_source_identity_digest();
    if (!source_digest || !source_identity) {
        return std::unexpected(!source_digest ? source_digest.error() : source_identity.error());
    }

    std::optional<std::string> candidate_digest;
    struct stat candidate_status{};
    if (::fstatat(
            target.parent_descriptor_fd(),
            candidate_name->c_str(),
            &candidate_status,
            AT_SYMLINK_NOFOLLOW
        ) == 0) {
        auto candidate =
            open_tree(target.parent_descriptor_fd(), *candidate_name, manifest.directory);
        if (!candidate) {
            return std::unexpected(candidate.error());
        }
        auto digest = tree_digest(candidate->get(), manifest.max_bytes);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        candidate_digest = std::move(*digest);
    } else if (errno != ENOENT) {
        return std::unexpected(error_message("inspect change apply recovery candidate"));
    }
    const auto state =
        classify_change_apply_recovery(reservation, *source_digest, candidate_digest);
    return change_apply_recovery_observation{
        .state = state,
        .candidate_name = std::move(*candidate_name),
        .current_source_identity_digest = std::move(*source_identity),
        .source_tree_digest = std::move(*source_digest),
        .candidate_tree_digest = std::move(candidate_digest),
    };
#endif
}

auto cleanup_finalized_change_apply_baseline(
    const change_apply_reservation_record& reservation,
    const change_apply_terminal_record& terminal,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<void> {
#if !defined(__linux__)
    (void)reservation;
    (void)terminal;
    (void)manifest;
    (void)target;
    return std::unexpected(std::string{"change apply cleanup is unsupported on this platform"});
#else
    if (auto valid = validate_bindings(reservation, manifest, target); !valid) {
        return std::unexpected(valid.error());
    }
    if (terminal.state != change_apply_terminal_state::applied ||
        terminal.grant_id != reservation.grant_id ||
        terminal.authorization_digest != reservation.authorization_digest ||
        terminal.manifest_digest != reservation.manifest_digest ||
        terminal.final_source_identity_digest.empty()) {
        return std::unexpected(std::string{"change apply cleanup terminal binding mismatch"});
    }
    if (auto parent = validate_parent_metadata(target.parent_descriptor_fd()); !parent) {
        return parent;
    }
    auto source = open_tree(target.parent_descriptor_fd(), target.basename(), manifest.directory);
    if (!source) {
        return std::unexpected(source.error());
    }
    auto source_identity = target.current_source_identity_digest();
    auto source_digest = tree_digest(source->get(), manifest.max_bytes);
    std::size_t source_entries = 0;
    if (!source_identity || *source_identity != terminal.final_source_identity_digest ||
        !source_digest || *source_digest != reservation.staged_tree_digest) {
        return std::unexpected(std::string{"change apply cleanup live source mismatch"});
    }
    if (auto valid = validate_tree_metadata(source->get(), source_entries, 0); !valid) {
        return valid;
    }

    auto candidate_name = change_apply_candidate_name(reservation.authorization_digest);
    if (!candidate_name) {
        return std::unexpected(candidate_name.error());
    }
    struct stat candidate_status{};
    if (::fstatat(
            target.parent_descriptor_fd(),
            candidate_name->c_str(),
            &candidate_status,
            AT_SYMLINK_NOFOLLOW
        ) != 0) {
        if (errno == ENOENT) {
            return {};
        }
        return std::unexpected(error_message("inspect finalized change apply baseline"));
    }
    auto candidate = open_tree(target.parent_descriptor_fd(), *candidate_name, manifest.directory);
    if (!candidate) {
        return std::unexpected(candidate.error());
    }
    std::size_t candidate_entries = 0;
    if (auto valid = validate_tree_metadata(candidate->get(), candidate_entries, 0); !valid) {
        return valid;
    }
    auto candidate_digest = tree_digest(candidate->get(), manifest.max_bytes);
    if (!candidate_digest || *candidate_digest != reservation.baseline_tree_digest) {
        return std::unexpected(std::string{"change apply cleanup baseline digest mismatch"});
    }
    if (manifest.directory) {
        if (auto removed = remove_directory_contents(candidate->get(), 0); !removed) {
            return removed;
        }
        if (::unlinkat(target.parent_descriptor_fd(), candidate_name->c_str(), AT_REMOVEDIR) != 0) {
            return std::unexpected(error_message("remove finalized change apply baseline"));
        }
    } else if (::unlinkat(target.parent_descriptor_fd(), candidate_name->c_str(), 0) != 0) {
        return std::unexpected(error_message("remove finalized change apply baseline"));
    }
    if (::fsync(target.parent_descriptor_fd()) != 0) {
        return std::unexpected(error_message("sync finalized change apply cleanup"));
    }
    return {};
#endif
}

auto discard_prepared_change_apply_candidate(
    const change_apply_reservation_record& reservation,
    const retained_change_manifest& manifest,
    const path_exposure_recovery_target& target
) -> result<void> {
#if !defined(__linux__)
    (void)reservation;
    (void)manifest;
    (void)target;
    return std::unexpected(
        std::string{"change apply candidate discard is unsupported on this platform"}
    );
#else
    if (auto valid = validate_bindings(reservation, manifest, target); !valid) {
        return std::unexpected(valid.error());
    }
    if (auto parent = validate_parent_metadata(target.parent_descriptor_fd()); !parent) {
        return parent;
    }
    auto observation = inspect_change_apply_exchange_recovery(reservation, manifest, target);
    if (!observation || observation->state != change_apply_recovery_state::candidate_prepared ||
        observation->current_source_identity_digest != reservation.source_identity_digest) {
        return std::unexpected(
            observation ? std::string{"change apply candidate is not safely discardable"}
                        : observation.error()
        );
    }
    auto source = open_tree(target.parent_descriptor_fd(), target.basename(), manifest.directory);
    auto candidate =
        open_tree(target.parent_descriptor_fd(), observation->candidate_name, manifest.directory);
    if (!source || !candidate) {
        return std::unexpected(!source ? source.error() : candidate.error());
    }
    std::size_t source_entries = 0;
    std::size_t candidate_entries = 0;
    if (auto valid = validate_tree_metadata(source->get(), source_entries, 0); !valid) {
        return valid;
    }
    if (auto valid = validate_tree_metadata(candidate->get(), candidate_entries, 0); !valid) {
        return valid;
    }
    if (manifest.directory) {
        if (auto removed = remove_directory_contents(candidate->get(), 0); !removed) {
            return removed;
        }
        if (::unlinkat(
                target.parent_descriptor_fd(), observation->candidate_name.c_str(), AT_REMOVEDIR
            ) != 0) {
            return std::unexpected(error_message("discard prepared change apply candidate"));
        }
    } else if (
        ::unlinkat(target.parent_descriptor_fd(), observation->candidate_name.c_str(), 0) != 0
    ) {
        return std::unexpected(error_message("discard prepared change apply candidate"));
    }
    if (::fsync(target.parent_descriptor_fd()) != 0) {
        return std::unexpected(error_message("sync prepared change apply candidate discard"));
    }
    return {};
#endif
}

} // namespace glove::supervisor
