#include "persistent_quota_image.hpp"

#include <fcntl.h>
#include <linux/loop.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::supervisor::linux_detail {

namespace {

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

    void reset(int descriptor = -1) noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_component(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 240U && value != "." && value != ".." &&
           value.find('/') == std::string_view::npos && value.find('\0') == std::string_view::npos;
}

auto valid_quota(std::uint64_t quota_bytes) -> bool {
    const long page_size = ::sysconf(_SC_PAGESIZE);
    return page_size > 0 && quota_bytes >= minimum_persistent_quota_bytes &&
           quota_bytes <= static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) &&
           quota_bytes % static_cast<std::uint64_t>(page_size) == 0;
}

auto formatter_path() -> result<std::string> {
    for (const auto* candidate : {"/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"}) {
        struct stat status{};
        if (::stat(candidate, &status) == 0 && S_ISREG(status.st_mode) && status.st_uid == 0 &&
            status.st_nlink == 1 && (status.st_mode & 0022U) == 0 &&
            ::access(candidate, X_OK) == 0) {
            return std::string{candidate};
        }
    }
    return std::unexpected(
        std::string{"retained image formatter is unavailable or not root-owned"}
    );
}

auto format_ext4(int image_fd) -> result<void> {
    auto formatter = formatter_path();
    if (!formatter) {
        return std::unexpected(formatter.error());
    }
    posix_spawn_file_actions_t actions{};
    int spawn_error = ::posix_spawn_file_actions_init(&actions);
    if (spawn_error != 0) {
        return std::unexpected(error_message("initialize retained formatter", spawn_error));
    }
    constexpr int child_image_fd = 9;
    spawn_error = ::posix_spawn_file_actions_adddup2(&actions, image_fd, child_image_fd);
    if (spawn_error != 0) {
        (void)::posix_spawn_file_actions_destroy(&actions);
        return std::unexpected(error_message("bind retained formatter image", spawn_error));
    }
    std::string executable = *formatter;
    std::string quiet = "-q";
    std::string force = "-F";
    std::string reserved_percentage = "-m";
    std::string zero = "0";
    std::string extended_options = "-E";
    std::string deterministic_initialization = "lazy_itable_init=0,lazy_journal_init=0";
    std::string image_path = "/proc/self/fd/" + std::to_string(child_image_fd);
    std::array<char*, 9> arguments{
        executable.data(),
        quiet.data(),
        force.data(),
        reserved_percentage.data(),
        zero.data(),
        extended_options.data(),
        deterministic_initialization.data(),
        image_path.data(),
        nullptr,
    };
    std::string path_environment = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    std::array<char*, 2> environment{path_environment.data(), nullptr};
    ::pid_t child = -1;
    spawn_error = ::posix_spawn(
        &child, executable.c_str(), &actions, nullptr, arguments.data(), environment.data()
    );
    (void)::posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        return std::unexpected(error_message("start retained formatter", spawn_error));
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return std::unexpected(error_message("wait for retained formatter"));
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::unexpected(std::string{"retained image formatter failed"});
    }
    return {};
}

auto attach_loop_and_mount(int image_fd, std::string_view mount_path) -> result<void> {
    unique_fd control{::open("/dev/loop-control", O_RDWR | O_CLOEXEC | O_NOFOLLOW)};
    if (control.get() < 0) {
        return std::unexpected(error_message("open retained loop control"));
    }
    const int index = ::ioctl(control.get(), LOOP_CTL_GET_FREE);
    if (index < 0) {
        return std::unexpected(error_message("allocate retained loop device"));
    }
    const std::string device = "/dev/loop" + std::to_string(index);
    unique_fd loop{::open(device.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW)};
    if (loop.get() < 0) {
        return std::unexpected(error_message("open retained loop device"));
    }
    if (::ioctl(loop.get(), LOOP_SET_FD, image_fd) != 0) {
        return std::unexpected(error_message("attach retained loop image"));
    }
    const auto clear_loop = [&] { (void)::ioctl(loop.get(), LOOP_CLR_FD, 0); };
    struct loop_info64 info{};
    info.lo_flags = LO_FLAGS_AUTOCLEAR;
    if (::ioctl(loop.get(), LOOP_SET_STATUS64, &info) != 0) {
        const auto message = error_message("configure retained loop device");
        clear_loop();
        return std::unexpected(message);
    }
    const std::string target{mount_path};
    constexpr unsigned long flags = MS_NOSUID | MS_NODEV;
    if (::mount(device.c_str(), target.c_str(), "ext4", flags, "errors=remount-ro") != 0) {
        const auto message = error_message("mount retained quota image");
        clear_loop();
        return std::unexpected(message);
    }
    return {};
}

auto open_valid_image(int root_fd, std::string_view image_name, std::uint64_t quota_bytes)
    -> result<unique_fd> {
    if (!valid_component(image_name) || !valid_quota(quota_bytes)) {
        return std::unexpected(std::string{"invalid retained quota image identity"});
    }
    const std::string name{image_name};
    unique_fd image{::openat(root_fd, name.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW)};
    if (image.get() < 0) {
        return std::unexpected(error_message("open retained quota image"));
    }
    struct stat status{};
    if (::fstat(image.get(), &status) != 0 || !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_uid != ::geteuid() || (status.st_mode & 0077U) != 0 || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) != quota_bytes) {
        return std::unexpected(std::string{"retained quota image metadata is invalid"});
    }
    return image;
}

} // namespace

auto persistent_quota_image_name(std::string_view directory_name) -> std::string {
    return std::string{directory_name} + ".ext4";
}

auto create_persistent_quota_image(
    int root_fd,
    std::string_view directory_name,
    std::string_view mount_path,
    std::uint64_t quota_bytes
) -> result<std::string> {
    if (root_fd < 0 || !valid_component(directory_name) || mount_path.empty() ||
        !valid_quota(quota_bytes)) {
        return std::unexpected(std::string{"invalid retained quota image request"});
    }
    const auto image_name = persistent_quota_image_name(directory_name);
    unique_fd image{::openat(
        root_fd, image_name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    )};
    if (image.get() < 0) {
        return std::unexpected(error_message("create retained quota image"));
    }
    const auto cleanup = [&] { (void)::unlinkat(root_fd, image_name.c_str(), 0); };
    if (::ftruncate(image.get(), static_cast<off_t>(quota_bytes)) != 0) {
        const auto message = error_message("size retained quota image");
        cleanup();
        return std::unexpected(message);
    }
    if (auto formatted = format_ext4(image.get()); !formatted) {
        cleanup();
        return std::unexpected(formatted.error());
    }
    if (::fsync(image.get()) != 0 || ::fsync(root_fd) != 0) {
        const auto message = error_message("sync retained quota image");
        cleanup();
        return std::unexpected(message);
    }
    if (auto mounted = attach_loop_and_mount(image.get(), mount_path); !mounted) {
        cleanup();
        return std::unexpected(mounted.error());
    }
    return image_name;
}

auto recover_persistent_quota_image(
    int root_fd, std::string_view image_name, std::string_view mount_path, std::uint64_t quota_bytes
) -> result<void> {
    if (root_fd < 0 || mount_path.empty()) {
        return std::unexpected(std::string{"invalid retained quota recovery request"});
    }
    auto image = open_valid_image(root_fd, image_name, quota_bytes);
    if (!image) {
        return std::unexpected(image.error());
    }
    return attach_loop_and_mount(image->get(), mount_path);
}

auto validate_persistent_quota_image(
    int root_fd, std::string_view image_name, std::uint64_t quota_bytes
) -> result<void> {
    auto image = open_valid_image(root_fd, image_name, quota_bytes);
    if (!image) {
        return std::unexpected(image.error());
    }
    return {};
}

auto remove_persistent_quota_image(int root_fd, std::string_view image_name) -> result<void> {
    if (root_fd < 0 || !valid_component(image_name)) {
        return std::unexpected(std::string{"invalid retained quota image cleanup request"});
    }
    const std::string name{image_name};
    if (::unlinkat(root_fd, name.c_str(), 0) != 0 && errno != ENOENT) {
        return std::unexpected(error_message("remove retained quota image"));
    }
    if (::fsync(root_fd) != 0) {
        return std::unexpected(error_message("sync retained quota image cleanup"));
    }
    return {};
}

auto persistent_quota_image_size(int root_fd, std::string_view image_name)
    -> result<std::uint64_t> {
    if (root_fd < 0 || !valid_component(image_name)) {
        return std::unexpected(std::string{"invalid retained quota image inspection request"});
    }
    const std::string name{image_name};
    unique_fd image{::openat(root_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (image.get() < 0) {
        return std::unexpected(error_message("open retained quota image"));
    }
    struct stat status{};
    if (::fstat(image.get(), &status) != 0 || !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_uid != ::geteuid() || (status.st_mode & 0077U) != 0 || status.st_size < 0) {
        return std::unexpected(std::string{"retained quota image metadata is invalid"});
    }
    const auto quota_bytes = static_cast<std::uint64_t>(status.st_size);
    if (!valid_quota(quota_bytes)) {
        return std::unexpected(std::string{"retained quota image size is invalid"});
    }
    return quota_bytes;
}

} // namespace glove::supervisor::linux_detail
