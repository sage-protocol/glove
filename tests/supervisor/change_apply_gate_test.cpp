#include "glove/supervisor/change_apply_gate.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-change-apply-gate-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

class descriptor {
public:
    explicit descriptor(const std::filesystem::path& path)
        : value_{::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)} {}

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_ = -1;
};

class accepting_verifier final : public glove::supervisor::change_apply_signature_verifier {
public:
    auto verify(
        const glove::supervisor::change_apply_authorization_claims& claims,
        std::span<const unsigned char> canonical_claims,
        std::string_view signature,
        std::uint64_t now_ms
    ) const -> glove::supervisor::result<void> override {
        if (claims.key_id != "admin-1" || canonical_claims.empty() ||
            signature != signature_value || now_ms < claims.issued_at_ms ||
            now_ms >= claims.expires_at_ms) {
            return std::unexpected(std::string{"signature rejected"});
        }
        return {};
    }

    static constexpr std::string_view signature_value = "dGVzdC1vbmx5LXNpZ25hdHVyZS12YWx1ZQ==";
};

auto run() -> int {
    using namespace glove::supervisor;

    temporary_directory baseline_root;
    temporary_directory staged_root;
    temporary_directory journal_root;
    REQUIRE(!baseline_root.root().empty());
    REQUIRE(!staged_root.root().empty());
    REQUIRE(!journal_root.root().empty());
    std::ofstream{baseline_root.root() / "file.txt"} << "before\n";
    std::ofstream{staged_root.root() / "file.txt"} << "after\n";
    descriptor baseline{baseline_root.root()};
    descriptor staged{staged_root.root()};
    REQUIRE(baseline.get() >= 0);
    REQUIRE(staged.get() >= 0);
    auto before = snapshot_path_tree(baseline.get(), 1'048'576);
    auto after = snapshot_path_tree(staged.get(), 1'048'576);
    REQUIRE(before.has_value());
    REQUIRE(after.has_value());
    auto manifest = build_retained_change_manifest(
        "session-1",
        "workspace",
        7,
        std::string(64, 'c'),
        std::string(64, 'd'),
        1'048'576,
        *before,
        *after
    );
    REQUIRE(manifest.has_value());

    const change_apply_authorization_claims claims{
        .schema_version = 1,
        .audience = "gloved",
        .key_id = "admin-1",
        .grant_id = "grant-1",
        .executor_node_id = "node-1",
        .session_id = manifest->session_id,
        .controller_plan_digest = std::string(64, 'a'),
        .plan_content_digest = std::string(64, 'b'),
        .exposure_id = manifest->exposure_id,
        .generation = manifest->generation,
        .scope_digest = manifest->scope_digest,
        .manifest_digest = manifest->manifest_digest,
        .policy_revision = 9,
        .issued_at_ms = 1'000,
        .expires_at_ms = 61'000,
    };
    auto authorization =
        encode_change_apply_authorization(claims, std::string{accepting_verifier::signature_value});
    REQUIRE(authorization.has_value());
    const change_apply_authorization_context context{
        .executor_node_id = claims.executor_node_id,
        .session_id = claims.session_id,
        .controller_plan_digest = claims.controller_plan_digest,
        .plan_content_digest = claims.plan_content_digest,
        .exposure_id = claims.exposure_id,
        .generation = claims.generation,
        .scope_digest = claims.scope_digest,
        .manifest_digest = claims.manifest_digest,
        .policy_revision = claims.policy_revision,
    };
    auto journal = change_apply_journal::open(journal_root.root() / "apply.journal");
    REQUIRE(journal.has_value());
    accepting_verifier verifier;
    auto reserved = verify_and_reserve_change_apply(
        authorization->canonical_json, context, *manifest, 2'000, verifier, *journal
    );
    REQUIRE(reserved.has_value());
    const auto stored = journal->find(claims.grant_id);
    REQUIRE(stored.has_value());
    REQUIRE(stored->reservation.source_identity_digest == manifest->source_identity_digest);
    REQUIRE(stored->reservation.baseline_tree_digest == manifest->baseline_tree_digest);
    REQUIRE(!verify_and_reserve_change_apply(
                 authorization->canonical_json, context, *manifest, 2'001, verifier, *journal
    )
                 .has_value());

    auto mismatched_manifest = *manifest;
    mismatched_manifest.exposure_id = "other";
    REQUIRE(
        !verify_and_reserve_change_apply(
             authorization->canonical_json, context, mismatched_manifest, 2'002, verifier, *journal
        )
             .has_value()
    );
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
