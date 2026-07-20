#include "glove/supervisor/path_exposure_journal.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace glove::supervisor {

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::array<unsigned char, 16> journal_magic = {
    'G', 'L', 'O', 'V', 'E', '-', 'E', 'X', 'P', 'O', 'S', 'U', 'R', 'E', '1', '\0'
};
constexpr std::uint64_t max_record_payload_bytes = 64U * 1024U;
constexpr std::size_t max_records = 4'096U;

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

private:
    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

} // namespace

namespace journal_wire {

struct wire_mode {
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::string cleanup_policy;
};

struct wire_descriptor {
    std::uint8_t schema_version = 0;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string root_id;
    std::string source_identity_digest;
    std::string scope_digest;
    std::string display_label;
    std::vector<wire_mode> allowed_modes;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::string> allowed_runtime_template_ids;
    std::string state;
};

struct wire_record {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string kind;
    wire_descriptor descriptor;
    std::string request_id;
    std::string request_digest;
    std::string host_path;
    std::string parent_identity_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string state;
    std::uint64_t revoked_at_ms = 0;
    std::string previous_hash;
    std::string record_hash;
};

} // namespace journal_wire

namespace {

using journal_wire::wire_descriptor;
using journal_wire::wire_mode;
using journal_wire::wire_record;

class canonical_encoder {
public:
    void append_u8(std::uint8_t value) { bytes_.push_back(value); }

    void append_u32(std::uint32_t value) {
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_u64(std::uint64_t value) {
        for (const unsigned int shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_string(std::string_view value) {
        append_u32(static_cast<std::uint32_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }

private:
    std::vector<unsigned char> bytes_;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto access_name(path_access access) -> std::string_view {
    switch (access) {
    case path_access::read:
        return "read";
    case path_access::ephemeral_write:
        return "ephemeral_write";
    case path_access::retained_write:
        return "retained_write";
    case path_access::direct_write:
        return "direct_write";
    }
    return {};
}

auto materialization_name(path_materialization materialization) -> std::string_view {
    switch (materialization) {
    case path_materialization::bind:
        return "bind";
    case path_materialization::snapshot:
        return "snapshot";
    case path_materialization::git_worktree:
        return "git_worktree";
    case path_materialization::copy:
        return "copy";
    }
    return {};
}

auto cleanup_name(path_cleanup_policy cleanup) -> std::string_view {
    switch (cleanup) {
    case path_cleanup_policy::retain:
        return "retain";
    case path_cleanup_policy::remove:
        return "remove";
    }
    return {};
}

auto state_name(path_exposure_state state) -> std::string_view {
    switch (state) {
    case path_exposure_state::active:
        return "active";
    case path_exposure_state::revoked:
        return "revoked";
    case path_exposure_state::expired:
        return "expired";
    }
    return {};
}

auto parse_access(std::string_view value) -> std::expected<path_access, std::string> {
    if (value == "read") {
        return path_access::read;
    }
    if (value == "ephemeral_write") {
        return path_access::ephemeral_write;
    }
    if (value == "retained_write") {
        return path_access::retained_write;
    }
    return std::unexpected(std::string{"invalid journal exposure access"});
}

auto parse_materialization(std::string_view value)
    -> std::expected<path_materialization, std::string> {
    if (value == "bind") {
        return path_materialization::bind;
    }
    if (value == "git_worktree") {
        return path_materialization::git_worktree;
    }
    if (value == "copy") {
        return path_materialization::copy;
    }
    return std::unexpected(std::string{"invalid journal exposure materialization"});
}

auto parse_cleanup(std::string_view value) -> std::expected<path_cleanup_policy, std::string> {
    if (value == "retain") {
        return path_cleanup_policy::retain;
    }
    if (value == "remove") {
        return path_cleanup_policy::remove;
    }
    return std::unexpected(std::string{"invalid journal exposure cleanup policy"});
}

auto parse_state(std::string_view value) -> std::expected<path_exposure_state, std::string> {
    if (value == "active") {
        return path_exposure_state::active;
    }
    if (value == "revoked") {
        return path_exposure_state::revoked;
    }
    if (value == "expired") {
        return path_exposure_state::expired;
    }
    return std::unexpected(std::string{"invalid journal exposure state"});
}

auto encode_descriptor(const path_exposure_descriptor& descriptor) -> wire_descriptor {
    std::vector<wire_mode> modes;
    modes.reserve(descriptor.allowed_modes.size());
    for (const auto& mode : descriptor.allowed_modes) {
        modes.push_back({
            .access = std::string{access_name(mode.access)},
            .materialization = std::string{materialization_name(mode.materialization)},
            .max_bytes = mode.max_bytes,
            .cleanup_policy = std::string{cleanup_name(mode.cleanup_policy)},
        });
    }
    return {
        .schema_version = descriptor.schema_version,
        .exposure_id = descriptor.exposure_id,
        .generation = descriptor.generation,
        .root_id = descriptor.root_id,
        .source_identity_digest = descriptor.source_identity_digest,
        .scope_digest = descriptor.scope_digest,
        .display_label = descriptor.display_label,
        .allowed_modes = std::move(modes),
        .expires_at_ms = descriptor.expires_at_ms,
        .allowed_runtime_template_ids = descriptor.allowed_runtime_template_ids,
        .state = std::string{state_name(descriptor.state)},
    };
}

auto decode_descriptor(const wire_descriptor& encoded) -> result<path_exposure_descriptor> {
    std::vector<path_exposure_mode> modes;
    modes.reserve(encoded.allowed_modes.size());
    for (const auto& mode : encoded.allowed_modes) {
        auto access = parse_access(mode.access);
        auto materialization = parse_materialization(mode.materialization);
        auto cleanup = parse_cleanup(mode.cleanup_policy);
        if (!access || !materialization || !cleanup) {
            return std::unexpected(std::string{"invalid journal exposure mode"});
        }
        modes.push_back({
            .access = *access,
            .materialization = *materialization,
            .max_bytes = mode.max_bytes,
            .cleanup_policy = *cleanup,
        });
    }
    auto state = parse_state(encoded.state);
    if (!state) {
        return std::unexpected(state.error());
    }
    return path_exposure_descriptor{
        .schema_version = encoded.schema_version,
        .exposure_id = encoded.exposure_id,
        .generation = encoded.generation,
        .root_id = encoded.root_id,
        .source_identity_digest = encoded.source_identity_digest,
        .scope_digest = encoded.scope_digest,
        .display_label = encoded.display_label,
        .allowed_modes = std::move(modes),
        .expires_at_ms = encoded.expires_at_ms,
        .allowed_runtime_template_ids = encoded.allowed_runtime_template_ids,
        .state = *state,
    };
}

auto encode_record(
    const path_exposure_journal_record& record,
    std::uint64_t sequence,
    std::string_view previous_hash
) -> wire_record {
    wire_record encoded;
    encoded.schema_version = 1;
    encoded.sequence = sequence;
    encoded.previous_hash = previous_hash;
    if (const auto* create = std::get_if<path_exposure_create_record>(&record)) {
        encoded.kind = "create";
        encoded.descriptor = encode_descriptor(create->descriptor);
        encoded.request_id = create->request_id;
        encoded.request_digest = create->request_digest;
        encoded.host_path = create->host_path;
        encoded.parent_identity_digest = create->parent_identity_digest;
    } else {
        const auto& revoke = std::get<path_exposure_revoke_record>(record);
        encoded.kind = "revoke";
        encoded.request_id = revoke.request_id;
        encoded.request_digest = revoke.request_digest;
        encoded.exposure_id = revoke.exposure_id;
        encoded.generation = revoke.generation;
        encoded.state = std::string{state_name(revoke.state)};
        encoded.revoked_at_ms = revoke.revoked_at_ms;
    }
    return encoded;
}

auto append_mode(canonical_encoder& encoder, const wire_mode& mode) -> void {
    encoder.append_string(mode.access);
    encoder.append_string(mode.materialization);
    encoder.append_u64(mode.max_bytes);
    encoder.append_string(mode.cleanup_policy);
}

auto record_digest(const wire_record& record) -> result<std::string> {
    canonical_encoder encoder;
    encoder.append_string("glove.path-exposure-journal-record");
    encoder.append_u8(1);
    encoder.append_u64(record.sequence);
    encoder.append_string(record.kind);
    if (record.kind == "create") {
        const auto& descriptor = record.descriptor;
        encoder.append_u8(descriptor.schema_version);
        encoder.append_string(descriptor.exposure_id);
        encoder.append_u64(descriptor.generation);
        encoder.append_string(descriptor.root_id);
        encoder.append_string(descriptor.source_identity_digest);
        encoder.append_string(descriptor.scope_digest);
        encoder.append_string(descriptor.display_label);
        encoder.append_u32(static_cast<std::uint32_t>(descriptor.allowed_modes.size()));
        for (const auto& mode : descriptor.allowed_modes) {
            append_mode(encoder, mode);
        }
        encoder.append_u64(descriptor.expires_at_ms);
        encoder.append_u32(
            static_cast<std::uint32_t>(descriptor.allowed_runtime_template_ids.size())
        );
        for (const auto& runtime : descriptor.allowed_runtime_template_ids) {
            encoder.append_string(runtime);
        }
        encoder.append_string(descriptor.state);
        encoder.append_string(record.request_id);
        encoder.append_string(record.request_digest);
        encoder.append_string(record.host_path);
        encoder.append_string(record.parent_identity_digest);
    } else {
        encoder.append_string(record.request_id);
        encoder.append_string(record.request_digest);
        encoder.append_string(record.exposure_id);
        encoder.append_u64(record.generation);
        encoder.append_string(record.state);
        encoder.append_u64(record.revoked_at_ms);
    }
    encoder.append_string(record.previous_hash);
    return container::sha256_hex(encoder.bytes());
}

auto decode_record(const wire_record& encoded) -> result<path_exposure_journal_record> {
    if (encoded.kind == "create") {
        auto descriptor = decode_descriptor(encoded.descriptor);
        if (!descriptor || descriptor->state != path_exposure_state::active ||
            encoded.request_id.empty() || !valid_digest(encoded.request_digest) ||
            encoded.host_path.empty() || !valid_digest(encoded.parent_identity_digest) ||
            !encoded.exposure_id.empty() || encoded.generation != 0 || !encoded.state.empty() ||
            encoded.revoked_at_ms != 0) {
            return std::unexpected(std::string{"invalid journal create record"});
        }
        return path_exposure_create_record{
            .descriptor = std::move(*descriptor),
            .request_id = encoded.request_id,
            .request_digest = encoded.request_digest,
            .host_path = encoded.host_path,
            .parent_identity_digest = encoded.parent_identity_digest,
        };
    }
    if (encoded.kind == "revoke") {
        auto state = parse_state(encoded.state);
        if (!state || *state == path_exposure_state::active || encoded.request_id.empty() ||
            !valid_digest(encoded.request_digest) || encoded.exposure_id.empty() ||
            encoded.generation == 0 || encoded.revoked_at_ms == 0 ||
            encoded.descriptor.schema_version != 0 || !encoded.host_path.empty() ||
            !encoded.parent_identity_digest.empty()) {
            return std::unexpected(std::string{"invalid journal revoke record"});
        }
        return path_exposure_revoke_record{
            .request_id = encoded.request_id,
            .request_digest = encoded.request_digest,
            .exposure_id = encoded.exposure_id,
            .generation = encoded.generation,
            .state = *state,
            .revoked_at_ms = encoded.revoked_at_ms,
        };
    }
    return std::unexpected(std::string{"unknown journal record kind"});
}

auto append_u32(std::vector<unsigned char>& bytes, std::uint32_t value) -> void {
    for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
        bytes.push_back(static_cast<unsigned char>(value >> shift));
    }
}

auto read_u32(std::span<const unsigned char, 4> bytes) -> std::uint32_t {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8U) | byte;
    }
    return value;
}

auto write_all_at(int descriptor, std::span<const unsigned char> bytes, std::uint64_t offset)
    -> std::expected<void, std::string> {
    std::size_t written = 0;
    while (written < bytes.size()) {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - written) {
            return std::unexpected(std::string{"exposure journal offset exceeds platform range"});
        }
        const auto result = ::pwrite(
            descriptor,
            bytes.data() + written,
            bytes.size() - written,
            static_cast<off_t>(offset + written)
        );
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(error_message("write exposure journal"));
        }
        written += static_cast<std::size_t>(result);
    }
    return {};
}

auto read_all_at(int descriptor, std::span<unsigned char> bytes, std::uint64_t offset)
    -> std::expected<void, std::string> {
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto result = ::pread(
            descriptor,
            bytes.data() + consumed,
            bytes.size() - consumed,
            static_cast<off_t>(offset + consumed)
        );
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(
                result < 0 ? error_message("read exposure journal")
                           : std::string{"exposure journal ended unexpectedly"}
            );
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
}

auto sync_descriptor(int descriptor) -> std::expected<void, std::string> {
    while (::fsync(descriptor) != 0) {
        if (errno != EINTR) {
            return std::unexpected(error_message("sync exposure journal"));
        }
    }
    return {};
}

auto validate_journal_file(int descriptor, std::uint64_t max_bytes)
    -> std::expected<std::uint64_t, std::string> {
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0) {
        return std::unexpected(error_message("inspect exposure journal"));
    }
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & 0777U;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        permissions != 0600U || metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_bytes) {
        return std::unexpected(
            std::string{"exposure journal must be a bounded owner-only single-link regular file"}
        );
    }
    return static_cast<std::uint64_t>(metadata.st_size);
}

struct opened_journal {
    unique_fd parent;
    unique_fd file;
    std::string filename;
    std::uint64_t size = 0;
};

auto open_journal(const std::filesystem::path& path, std::uint64_t max_bytes)
    -> std::expected<opened_journal, std::string> {
    if (!path.is_absolute() || path.filename().empty()) {
        return std::unexpected(std::string{"exposure journal path must be absolute"});
    }
    const auto parent_path = path.parent_path();
    unique_fd parent{::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (parent.get() < 0) {
        return std::unexpected(error_message("open exposure journal parent"));
    }
    struct stat parent_metadata{};
    if (::fstat(parent.get(), &parent_metadata) != 0 || !S_ISDIR(parent_metadata.st_mode) ||
        parent_metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(parent_metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"exposure journal parent must be owner-only"});
    }
    const auto filename = path.filename().string();
    int descriptor = ::openat(parent.get(), filename.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    bool created = false;
    if (descriptor < 0 && errno == ENOENT) {
        descriptor = ::openat(
            parent.get(), filename.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
        );
        created = descriptor >= 0;
    }
    if (descriptor < 0) {
        return std::unexpected(error_message("open exposure journal"));
    }
    unique_fd file{descriptor};
    while (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno != EINTR) {
            return std::unexpected(error_message("lock exposure journal"));
        }
    }
    auto size = validate_journal_file(file.get(), max_bytes);
    if (!size) {
        if (created) {
            (void)::unlinkat(parent.get(), filename.c_str(), 0);
            (void)sync_descriptor(parent.get());
        }
        return std::unexpected(size.error());
    }
    if (created) {
        const auto discard_created = [&] {
            (void)::unlinkat(parent.get(), filename.c_str(), 0);
            (void)sync_descriptor(parent.get());
        };
        if (max_bytes < journal_magic.size()) {
            discard_created();
            return std::unexpected(std::string{"exposure journal capacity is too small"});
        }
        if (auto written = write_all_at(file.get(), journal_magic, 0); !written) {
            discard_created();
            return std::unexpected(written.error());
        }
        if (auto synced = sync_descriptor(file.get()); !synced) {
            discard_created();
            return std::unexpected(synced.error());
        }
        if (auto synced = sync_descriptor(parent.get()); !synced) {
            discard_created();
            return std::unexpected(synced.error());
        }
        *size = journal_magic.size();
    }
    return opened_journal{
        .parent = std::move(parent),
        .file = std::move(file),
        .filename = filename,
        .size = *size,
    };
}

auto make_frame(std::string_view payload) -> std::vector<unsigned char> {
    std::vector<unsigned char> frame;
    frame.reserve(payload.size() + 8U);
    append_u32(frame, static_cast<std::uint32_t>(payload.size()));
    frame.insert(frame.end(), payload.begin(), payload.end());
    append_u32(frame, static_cast<std::uint32_t>(payload.size()));
    return frame;
}

} // namespace

struct path_exposure_journal::implementation {
    opened_journal opened;
    std::uint64_t max_bytes = 0;
    std::uint64_t sequence = 0;
    std::string head_hash = std::string(64, '0');
    std::vector<path_exposure_journal_record> records;
};

path_exposure_journal::path_exposure_journal(
    construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {
    (void)token;
}

path_exposure_journal::path_exposure_journal(path_exposure_journal&&) noexcept = default;

auto path_exposure_journal::operator=(path_exposure_journal&&) noexcept
    -> path_exposure_journal& = default;

path_exposure_journal::~path_exposure_journal() = default;

auto path_exposure_journal::open(const std::filesystem::path& path, std::uint64_t max_bytes)
    -> result<path_exposure_journal> {
    if (max_bytes < journal_magic.size() + 8U) {
        return std::unexpected(std::string{"exposure journal capacity is invalid"});
    }
    auto opened = open_journal(path, max_bytes);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    if (opened->size < journal_magic.size()) {
        return std::unexpected(std::string{"exposure journal header is truncated"});
    }
    std::array<unsigned char, journal_magic.size()> header{};
    if (auto read = read_all_at(opened->file.get(), header, 0); !read) {
        return std::unexpected(read.error());
    }
    if (!std::ranges::equal(header, journal_magic)) {
        return std::unexpected(std::string{"exposure journal header is invalid"});
    }

    auto state = std::make_unique<implementation>();
    state->opened = std::move(*opened);
    state->max_bytes = max_bytes;
    std::uint64_t offset = journal_magic.size();
    while (offset < state->opened.size) {
        if (state->records.size() >= max_records || state->opened.size - offset < 8U) {
            return std::unexpected(std::string{"exposure journal record framing is invalid"});
        }
        std::array<unsigned char, 4> prefix{};
        if (auto read = read_all_at(state->opened.file.get(), prefix, offset); !read) {
            return std::unexpected(read.error());
        }
        const auto payload_bytes = read_u32(prefix);
        if (payload_bytes == 0 || payload_bytes > max_record_payload_bytes ||
            state->opened.size - offset < static_cast<std::uint64_t>(payload_bytes) + 8U) {
            return std::unexpected(std::string{"exposure journal record length is invalid"});
        }
        std::string payload(payload_bytes, '\0');
        if (auto read = read_all_at(
                state->opened.file.get(),
                std::span{reinterpret_cast<unsigned char*>(payload.data()), payload.size()},
                offset + 4U
            );
            !read) {
            return std::unexpected(read.error());
        }
        std::array<unsigned char, 4> suffix{};
        if (auto read = read_all_at(state->opened.file.get(), suffix, offset + 4U + payload_bytes);
            !read || read_u32(suffix) != payload_bytes) {
            return std::unexpected(std::string{"exposure journal record framing mismatch"});
        }
        wire_record encoded;
        if (const auto error = glz::read<strict_read_options>(encoded, payload); error) {
            return std::unexpected(std::string{"exposure journal record schema is invalid"});
        }
        if (encoded.schema_version != 1 || encoded.sequence != state->sequence + 1U ||
            encoded.previous_hash != state->head_hash || !valid_digest(encoded.record_hash)) {
            return std::unexpected(std::string{"exposure journal chain metadata is invalid"});
        }
        auto digest = record_digest(encoded);
        if (!digest || *digest != encoded.record_hash) {
            return std::unexpected(std::string{"exposure journal record hash mismatch"});
        }
        auto decoded = decode_record(encoded);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        state->records.push_back(std::move(*decoded));
        state->sequence = encoded.sequence;
        state->head_hash = encoded.record_hash;
        offset += static_cast<std::uint64_t>(payload_bytes) + 8U;
    }
    return path_exposure_journal{construction_token{}, std::move(state)};
}

auto path_exposure_journal::records() const -> const std::vector<path_exposure_journal_record>& {
    return state_->records;
}

auto path_exposure_journal::append(const path_exposure_journal_record& record)
    -> std::expected<void, std::string> {
    if (!state_ || state_->records.size() >= max_records ||
        state_->sequence == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(std::string{"exposure journal capacity is exhausted"});
    }
    auto encoded = encode_record(record, state_->sequence + 1U, state_->head_hash);
    auto digest = record_digest(encoded);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    encoded.record_hash = *digest;
    auto payload = glz::write_json(encoded);
    if (!payload || payload->empty() || payload->size() > max_record_payload_bytes) {
        return std::unexpected(std::string{"exposure journal record encoding is invalid"});
    }
    auto decoded = decode_record(encoded);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    const auto frame = make_frame(*payload);
    if (frame.size() > state_->max_bytes ||
        state_->opened.size > state_->max_bytes - frame.size()) {
        return std::unexpected(std::string{"exposure journal byte capacity is exhausted"});
    }
    const auto original_size = state_->opened.size;
    if (auto written = write_all_at(state_->opened.file.get(), frame, original_size); !written) {
        (void)::ftruncate(state_->opened.file.get(), static_cast<off_t>(original_size));
        return std::unexpected(written.error());
    }
    if (auto synced = sync_descriptor(state_->opened.file.get()); !synced) {
        (void)::ftruncate(state_->opened.file.get(), static_cast<off_t>(original_size));
        (void)sync_descriptor(state_->opened.file.get());
        return std::unexpected(synced.error());
    }
    state_->opened.size += frame.size();
    state_->sequence = encoded.sequence;
    state_->head_hash = encoded.record_hash;
    state_->records.push_back(std::move(*decoded));
    return {};
}

} // namespace glove::supervisor
