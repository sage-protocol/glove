#include "linux_process_identity.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace glove::control::linux_detail {

namespace {

constexpr std::size_t max_proc_file_bytes = 64U * 1024U;
constexpr std::size_t max_cgroup_path_bytes = 4U * 1024U;
constexpr std::size_t digest_hex_bytes = 64U;

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

auto read_bounded(int descriptor, std::string_view label)
    -> std::expected<std::string, std::string> {
    std::string output;
    output.reserve(512U);
    char chunk[4096]{};
    for (;;) {
        const auto count = ::read(descriptor, chunk, sizeof(chunk));
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(error_message(std::string{"read "} + std::string{label}));
        }
        if (count == 0) {
            return output;
        }
        const auto size = static_cast<std::size_t>(count);
        if (size > max_proc_file_bytes - output.size()) {
            return std::unexpected(std::string{label} + " exceeds its bound");
        }
        output.append(chunk, size);
    }
}

auto read_file_at(int directory, const char* name, std::string_view label)
    -> std::expected<std::string, std::string> {
    // procfs and cgroupfs are kernel-owned; no-follow prevents substitution by
    // any mount namespace path that unexpectedly contains a symlink.
    unique_fd descriptor{::openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(error_message(std::string{"open "} + std::string{label}));
    }
    return read_bounded(descriptor.get(), label);
}

auto valid_boot_id(std::string_view value) noexcept -> bool {
    if (value.size() != 36U) {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (value[index] != '-') {
                return false;
            }
            continue;
        }
        const auto byte = static_cast<unsigned char>(value[index]);
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
            return false;
        }
    }
    return true;
}

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == digest_hex_bytes && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto read_boot_id() -> std::expected<std::string, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd descriptor{
        ::open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (descriptor.get() < 0) {
        return std::unexpected(error_message("open Linux boot identity"));
    }
    auto value = read_bounded(descriptor.get(), "Linux boot identity");
    if (!value) {
        return value;
    }
    while (!value->empty() && (value->back() == '\n' || value->back() == '\r')) {
        value->pop_back();
    }
    if (!valid_boot_id(*value)) {
        return std::unexpected(std::string{"Linux boot identity is invalid"});
    }
    return value;
}

auto parse_start_time(std::string_view stat) -> std::expected<std::uint64_t, std::string> {
    const auto command_end = stat.rfind(')');
    if (command_end == std::string_view::npos || command_end + 2U >= stat.size() ||
        stat[command_end + 1U] != ' ') {
        return std::unexpected(std::string{"Linux process stat command is malformed"});
    }
    auto fields = stat.substr(command_end + 2U);
    // The suffix begins at field 3 (state); starttime is field 22.
    for (unsigned int field = 3U; field <= 22U; ++field) {
        const auto end = fields.find(' ');
        const auto token = fields.substr(0, end);
        if (token.empty()) {
            return std::unexpected(std::string{"Linux process stat fields are malformed"});
        }
        if (field == 22U) {
            std::uint64_t parsed = 0;
            const auto result = std::from_chars(token.data(), token.data() + token.size(), parsed);
            if (result.ec != std::errc{} || result.ptr != token.data() + token.size() ||
                parsed == 0) {
                return std::unexpected(std::string{"Linux process start time is invalid"});
            }
            return parsed;
        }
        if (end == std::string_view::npos) {
            return std::unexpected(std::string{"Linux process stat ended before start time"});
        }
        fields.remove_prefix(end + 1U);
    }
    return std::unexpected(std::string{"Linux process start time is missing"});
}

auto parse_cgroup_path(std::string_view content) -> std::expected<std::string, std::string> {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const auto end = content.find('\n', offset);
        const auto line = content.substr(
            offset, end == std::string_view::npos ? content.size() - offset : end - offset
        );
        if (line.starts_with("0::")) {
            const auto path = line.substr(3U);
            if (path.empty() || path.front() != '/' || path.size() > max_cgroup_path_bytes ||
                (path.size() > 1U && path.back() == '/') ||
                path.find('\0') != std::string_view::npos) {
                return std::unexpected(std::string{"unified cgroup path is invalid"});
            }
            std::size_t component_offset = 1U;
            while (component_offset < path.size()) {
                const auto separator = path.find('/', component_offset);
                const auto component = path.substr(
                    component_offset,
                    separator == std::string_view::npos ? path.size() - component_offset
                                                        : separator - component_offset
                );
                if (component.empty() || component == "." || component == "..") {
                    return std::unexpected(std::string{"unified cgroup path is not canonical"});
                }
                if (separator == std::string_view::npos) {
                    break;
                }
                component_offset = separator + 1U;
            }
            return std::string{path};
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1U;
    }
    return std::unexpected(std::string{"unified cgroup membership is missing"});
}

struct cgroup_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::string path_digest;
};

auto inspect_cgroup(std::string_view path) -> std::expected<cgroup_identity, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd current{::open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (current.get() < 0) {
        return std::unexpected(error_message("open cgroup v2 root"));
    }
    std::size_t offset = 1U;
    while (offset < path.size()) {
        const auto separator = path.find('/', offset);
        const auto component = path.substr(
            offset, separator == std::string_view::npos ? path.size() - offset : separator - offset
        );
        const std::string name{component};
        unique_fd next{
            ::openat(current.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (next.get() < 0) {
            return std::unexpected(error_message("open process cgroup component"));
        }
        current = std::move(next);
        if (separator == std::string_view::npos) {
            break;
        }
        offset = separator + 1U;
    }

    struct stat metadata{};

    if (::fstat(current.get(), &metadata) != 0) {
        return std::unexpected(error_message("inspect process cgroup"));
    }
    if (!S_ISDIR(metadata.st_mode)) {
        return std::unexpected(std::string{"process cgroup is not a directory"});
    }
    using unsigned_device = std::make_unsigned_t<decltype(metadata.st_dev)>;
    using unsigned_inode = std::make_unsigned_t<decltype(metadata.st_ino)>;
    const auto device = static_cast<std::uint64_t>(static_cast<unsigned_device>(metadata.st_dev));
    const auto inode = static_cast<std::uint64_t>(static_cast<unsigned_inode>(metadata.st_ino));
    if (device == 0 || inode == 0) {
        return std::unexpected(std::string{"process cgroup identity is invalid"});
    }
    const auto material = std::string{"glove.linux-cgroup-path:"} + std::string{path};
    auto digest = container::sha256_hex(
        std::span<const unsigned char>{
            std::bit_cast<const unsigned char*>(material.data()), material.size()
        }
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return cgroup_identity{.device = device, .inode = inode, .path_digest = std::move(*digest)};
}

auto capture_from_directory(std::uint32_t pid, int process_directory)
    -> std::expected<linux_process_identity, std::string> {
    auto boot_id = read_boot_id();
    auto first_stat = read_file_at(process_directory, "stat", "Linux process stat");
    auto first_cgroup = read_file_at(process_directory, "cgroup", "Linux process cgroup");
    if (!boot_id || !first_stat || !first_cgroup) {
        if (!boot_id) {
            return std::unexpected(boot_id.error());
        }
        return std::unexpected(first_stat ? first_cgroup.error() : first_stat.error());
    }
    auto start_time = parse_start_time(*first_stat);
    auto cgroup_path = parse_cgroup_path(*first_cgroup);
    if (!start_time || !cgroup_path) {
        return std::unexpected(start_time ? cgroup_path.error() : start_time.error());
    }
    auto cgroup = inspect_cgroup(*cgroup_path);
    if (!cgroup) {
        return std::unexpected(cgroup.error());
    }
    auto second_stat = read_file_at(process_directory, "stat", "Linux process stat recheck");
    auto second_cgroup = read_file_at(process_directory, "cgroup", "Linux process cgroup recheck");
    if (!second_stat || !second_cgroup) {
        return std::unexpected(second_stat ? second_cgroup.error() : second_stat.error());
    }
    auto second_start_time = parse_start_time(*second_stat);
    auto second_cgroup_path = parse_cgroup_path(*second_cgroup);
    if (!second_start_time || !second_cgroup_path || *second_start_time != *start_time ||
        *second_cgroup_path != *cgroup_path) {
        return std::unexpected(std::string{"Linux process identity changed while capturing"});
    }
    return linux_process_identity{
        .schema_version = 1,
        .pid = pid,
        .boot_id = std::move(*boot_id),
        .start_time_ticks = *start_time,
        .cgroup_device = cgroup->device,
        .cgroup_inode = cgroup->inode,
        .cgroup_path_digest = std::move(cgroup->path_digest),
    };
}

auto open_process_directory(std::uint32_t pid)
    -> std::expected<std::optional<unique_fd>, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd proc{::open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (proc.get() < 0) {
        return std::unexpected(error_message("open procfs"));
    }
    const auto name = std::to_string(pid);
    unique_fd process{
        ::openat(proc.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (process.get() < 0) {
        if (errno == ENOENT || errno == ESRCH) {
            return std::optional<unique_fd>{};
        }
        return std::unexpected(error_message("open Linux process directory"));
    }
    return std::optional<unique_fd>{std::move(process)};
}

auto valid_identity(const linux_process_identity& identity) noexcept -> bool {
    return identity.schema_version == 1 && identity.pid > 0 && valid_boot_id(identity.boot_id) &&
           identity.start_time_ticks > 0 && identity.cgroup_device > 0 &&
           identity.cgroup_inode > 0 && valid_digest(identity.cgroup_path_digest) &&
           static_cast<std::uint64_t>(identity.pid) <=
               static_cast<std::uint64_t>(std::numeric_limits<::pid_t>::max());
}

} // namespace

auto capture_linux_process_identity(::pid_t pid)
    -> std::expected<linux_process_identity, std::string> {
    if (pid <= 0 || static_cast<std::uint64_t>(pid) >
                        static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::unexpected(std::string{"Linux process PID is invalid"});
    }
    const auto bounded_pid = static_cast<std::uint32_t>(pid);
    auto directory = open_process_directory(bounded_pid);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    auto opened = std::move(*directory);
    if (!opened.has_value()) {
        return std::unexpected(std::string{"Linux process does not exist"});
    }
    return capture_from_directory(bounded_pid, opened->get());
}

auto observe_linux_process_identity(const linux_process_identity& expected)
    -> std::expected<linux_process_identity_observation, std::string> {
    if (!valid_identity(expected)) {
        return std::unexpected(std::string{"expected Linux process identity is invalid"});
    }
    auto directory = open_process_directory(expected.pid);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    auto opened = std::move(*directory);
    if (!opened.has_value()) {
        return linux_process_identity_observation::absent;
    }
    auto observed = capture_from_directory(expected.pid, opened->get());
    if (!observed) {
        return std::unexpected(observed.error());
    }
    return *observed == expected ? linux_process_identity_observation::exact
                                 : linux_process_identity_observation::mismatch;
}

} // namespace glove::control::linux_detail
