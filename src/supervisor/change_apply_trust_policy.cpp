#include "glove/supervisor/change_apply_trust_policy.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace glove::supervisor {

namespace apply_trust_wire {

struct key {
    std::string key_id;
    std::string algorithm;
    std::string public_key_base64url;
    std::uint64_t not_before_ms = 0;
    std::uint64_t not_after_ms = 0;
};

struct policy {
    std::uint8_t schema_version = 0;
    std::uint64_t revision = 0;
    std::vector<key> keys;
};

} // namespace apply_trust_wire

namespace {

constexpr std::uint64_t max_policy_bytes = std::uint64_t{64} * 1024U;
constexpr std::size_t max_keys = 16U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

class unique_fd {
public:
    explicit unique_fd(int descriptor) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;
    unique_fd(unique_fd&&) = delete;
    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto modification_time_matches(const struct stat& left, const struct stat& right) -> bool {
#if defined(__APPLE__)
    return left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
           left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec;
#else
    return left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec;
#endif
}

auto same_file(const struct stat& left, const struct stat& right) -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
           left.st_nlink == right.st_nlink && left.st_size == right.st_size &&
           modification_time_matches(left, right);
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_ed25519_key(std::string_view value) -> bool {
    // 32 bytes encoded as unpadded base64url.
    constexpr std::string_view canonical_final_characters = "AEIMQUYcgkosw048";
    return value.size() == 43U &&
           std::ranges::all_of(
               value,
               [](unsigned char byte) {
                   return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                          (byte >= '0' && byte <= '9') || byte == '-' || byte == '_';
               }
           ) &&
           canonical_final_characters.contains(value.back());
}

auto load_file(const std::filesystem::path& path) -> result<std::string> {
    if (!path.is_absolute()) {
        return std::unexpected(std::string{"change apply trust policy path must be absolute"});
    }
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(error_message("open change apply trust policy"));
    }
    struct stat before{};
    if (::fstat(descriptor.get(), &before) != 0) {
        return std::unexpected(error_message("inspect change apply trust policy"));
    }
    const auto permissions = static_cast<unsigned int>(before.st_mode) & 0777U;
    if (!S_ISREG(before.st_mode) || before.st_uid != ::geteuid() || before.st_nlink != 1 ||
        permissions != 0600U || before.st_size <= 0 ||
        static_cast<std::uint64_t>(before.st_size) > max_policy_bytes ||
        static_cast<std::uint64_t>(before.st_size) >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::unexpected(
            std::string{"change apply trust policy must be a bounded owner-only single-link file"}
        );
    }
    std::string contents(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto read = ::pread(
            descriptor.get(),
            contents.data() + consumed,
            contents.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(
                read < 0 ? error_message("read change apply trust policy")
                         : std::string{"change apply trust policy ended unexpectedly"}
            );
        }
        consumed += static_cast<std::size_t>(read);
    }
    struct stat after{};
    if (::fstat(descriptor.get(), &after) != 0 || !same_file(before, after)) {
        return std::unexpected(std::string{"change apply trust policy changed while loading"});
    }
    return contents;
}

} // namespace

change_apply_trust_policy::change_apply_trust_policy(
    std::uint64_t revision, std::vector<change_apply_trust_key> keys
)
    : revision_{revision}, keys_{std::move(keys)} {}

auto change_apply_trust_policy::load(const std::filesystem::path& path)
    -> result<change_apply_trust_policy> {
    auto contents = load_file(path);
    if (!contents) {
        return std::unexpected(contents.error());
    }
    apply_trust_wire::policy encoded;
    if (const auto error = glz::read<strict_read_options>(encoded, *contents);
        error || encoded.schema_version != 1 || encoded.revision == 0 || encoded.keys.empty() ||
        encoded.keys.size() > max_keys) {
        return std::unexpected(std::string{"change apply trust policy schema is invalid"});
    }
    std::vector<change_apply_trust_key> keys;
    keys.reserve(encoded.keys.size());
    std::string previous_key_id;
    for (auto& key : encoded.keys) {
        if (!valid_identifier(key.key_id) || key.algorithm != "ed25519" ||
            !valid_ed25519_key(key.public_key_base64url) || key.not_before_ms == 0 ||
            key.not_after_ms <= key.not_before_ms ||
            (!previous_key_id.empty() && previous_key_id >= key.key_id)) {
            return std::unexpected(std::string{"change apply trust policy key is invalid"});
        }
        previous_key_id = key.key_id;
        keys.push_back({
            .key_id = std::move(key.key_id),
            .algorithm = std::move(key.algorithm),
            .public_key_base64url = std::move(key.public_key_base64url),
            .not_before_ms = key.not_before_ms,
            .not_after_ms = key.not_after_ms,
        });
    }
    return change_apply_trust_policy{encoded.revision, std::move(keys)};
}

auto change_apply_trust_policy::active_key(std::string_view key_id, std::uint64_t now_ms) const
    -> result<const change_apply_trust_key*> {
    const auto found = std::ranges::lower_bound(keys_, key_id, {}, &change_apply_trust_key::key_id);
    if (found == keys_.end() || found->key_id != key_id) {
        return std::unexpected(std::string{"change apply trust key is not configured"});
    }
    if (now_ms < found->not_before_ms || now_ms >= found->not_after_ms) {
        return std::unexpected(std::string{"change apply trust key is not currently active"});
    }
    return &*found;
}

auto change_apply_trust_policy::authorization_key(
    std::string_view key_id,
    std::uint64_t issued_at_ms,
    std::uint64_t expires_at_ms,
    std::uint64_t now_ms
) const -> result<const change_apply_trust_key*> {
    auto key = active_key(key_id, now_ms);
    if (!key) {
        return std::unexpected(key.error());
    }
    if (issued_at_ms < (*key)->not_before_ms || expires_at_ms <= issued_at_ms ||
        expires_at_ms > (*key)->not_after_ms) {
        return std::unexpected(
            std::string{"change apply authorization exceeds the trust key validity window"}
        );
    }
    return *key;
}

} // namespace glove::supervisor
