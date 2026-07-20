#include "glove/supervisor/change_apply_gate.hpp"
#include "glove/supervisor/change_apply_recovery.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

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
        std::string pattern = "/tmp/glove-change-apply-exchange-test-XXXXXX";
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
    descriptor(const std::filesystem::path& path, bool directory) {
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
        if (directory) {
            flags |= O_DIRECTORY;
        }
        value_ = ::open(path.c_str(), flags);
    }

    descriptor(int parent, std::string_view name, bool directory) {
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
        if (directory) {
            flags |= O_DIRECTORY;
        }
        const std::string component{name};
        value_ = ::openat(parent, component.c_str(), flags);
    }

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_ = -1;
};

#if defined(__linux__)

constexpr std::uint64_t stage_bytes = std::uint64_t{32} * 1024U * 1024U;

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

auto retained_mode() -> glove::supervisor::path_exposure_mode {
    using namespace glove::supervisor;
    return {
        .access = path_access::retained_write,
        .materialization = path_materialization::copy,
        .max_bytes = stage_bytes,
        .cleanup_policy = path_cleanup_policy::retain,
    };
}

auto create_request(
    const std::filesystem::path& source, std::string request_id, std::string exposure_id
) -> glove::supervisor::path_exposure_create_request {
    return {
        .request_id = std::move(request_id),
        .exposure_id = std::move(exposure_id),
        .root_id = "projects",
        .host_path = source.string(),
        .display_label = "apply test",
        .allowed_modes = {retained_mode()},
        .ttl_secs = 3'600,
        .allowed_runtime_template_ids = {"codex-safe"},
    };
}

auto reservation_for(const glove::supervisor::retained_change_manifest& manifest, char marker)
    -> glove::supervisor::change_apply_reservation_record {
    return {
        .grant_id = std::string{"grant-"} + marker,
        .authorization_digest = std::string(64, marker),
        .manifest_digest = manifest.manifest_digest,
        .session_id = manifest.session_id,
        .exposure_id = manifest.exposure_id,
        .generation = manifest.generation,
        .scope_digest = manifest.scope_digest,
        .source_identity_digest = manifest.source_identity_digest,
        .baseline_tree_digest = manifest.baseline_tree_digest,
        .staged_tree_digest = manifest.staged_tree_digest,
        .reserved_at_ms = 2'000,
    };
}

struct authorization_fixture {
    glove::supervisor::change_apply_authorization authorization;
    glove::supervisor::change_apply_authorization_context context;
};

auto authorization_for(
    const glove::supervisor::retained_change_manifest& manifest, std::string grant_id
) -> glove::supervisor::result<authorization_fixture> {
    using namespace glove::supervisor;
    const change_apply_authorization_claims claims{
        .schema_version = 1,
        .audience = "gloved",
        .key_id = "admin-1",
        .grant_id = std::move(grant_id),
        .executor_node_id = "node-1",
        .session_id = manifest.session_id,
        .controller_plan_digest = std::string(64, '1'),
        .plan_content_digest = std::string(64, '2'),
        .exposure_id = manifest.exposure_id,
        .generation = manifest.generation,
        .scope_digest = manifest.scope_digest,
        .manifest_digest = manifest.manifest_digest,
        .policy_revision = 9,
        .issued_at_ms = 1'000,
        .expires_at_ms = 61'000,
    };
    auto authorization =
        encode_change_apply_authorization(claims, std::string{accepting_verifier::signature_value});
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    return authorization_fixture{
        .authorization = std::move(*authorization),
        .context = {
            .executor_node_id = claims.executor_node_id,
            .session_id = claims.session_id,
            .controller_plan_digest = claims.controller_plan_digest,
            .plan_content_digest = claims.plan_content_digest,
            .exposure_id = claims.exposure_id,
            .generation = claims.generation,
            .scope_digest = claims.scope_digest,
            .manifest_digest = claims.manifest_digest,
            .policy_revision = claims.policy_revision,
        },
    };
}

auto manifest_for(
    const std::filesystem::path& source,
    const std::filesystem::path& stage,
    const glove::supervisor::path_exposure_descriptor& exposure,
    std::string session_id,
    bool directory
) -> glove::supervisor::result<glove::supervisor::retained_change_manifest> {
    using namespace glove::supervisor;
    descriptor source_descriptor{source, directory};
    descriptor stage_descriptor{stage, directory};
    if (source_descriptor.get() < 0 || stage_descriptor.get() < 0) {
        return std::unexpected(std::string{"open test manifest trees"});
    }
    auto baseline = snapshot_path_tree(source_descriptor.get(), stage_bytes);
    auto staged = snapshot_path_tree(stage_descriptor.get(), stage_bytes);
    if (!baseline || !staged) {
        return std::unexpected(!baseline ? baseline.error() : staged.error());
    }
    return build_retained_change_manifest(
        std::move(session_id),
        exposure.exposure_id,
        exposure.generation,
        exposure.scope_digest,
        exposure.source_identity_digest,
        stage_bytes,
        *baseline,
        *staged
    );
}

auto read_text(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

auto publish_file_stage(
    const std::filesystem::path& materialization_root,
    const glove::supervisor::retained_change_manifest& manifest,
    const std::filesystem::path& payload
) -> bool {
    const auto name = "glove-retained-s" + std::to_string(manifest.session_id.size()) + "-" +
                      manifest.session_id + "-a" + std::to_string(manifest.exposure_id.size()) +
                      "-" + manifest.exposure_id;
    const auto stage = materialization_root / name;
    const auto content = stage / "content";
    if (!std::filesystem::create_directory(materialization_root) ||
        ::chmod(materialization_root.c_str(), 0700) != 0 ||
        !std::filesystem::create_directory(stage) || ::chmod(stage.c_str(), 0700) != 0 ||
        !std::filesystem::create_directory(content) || ::chmod(content.c_str(), 0700) != 0) {
        return false;
    }
    std::ofstream output{stage / "manifest.json"};
    output << manifest.canonical_json;
    output.close();
    return output && std::filesystem::copy_file(payload, content / ".glove-payload");
}

#endif

auto run() -> int {
    using namespace glove::supervisor;
    REQUIRE(
        !change_apply_host_space_eligible(default_change_apply_free_space_reserve_bytes - 1U, 0)
    );
    REQUIRE(change_apply_host_space_eligible(
        default_change_apply_free_space_reserve_bytes + 4'096U, 4'096U
    ));
    REQUIRE(!change_apply_host_space_eligible(
        std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max(), 1U
    ));
#if !defined(__linux__)
    return 0;
#else
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto protected_root = temporary.root() / "projects";
    REQUIRE(std::filesystem::create_directory(protected_root));
    path_exposure_root_policy policy{
        .root_id = "projects",
        .host_root = std::filesystem::canonical(protected_root).string(),
        .allowed_modes = {retained_mode()},
        .max_ttl_secs = 7'200,
        .allowed_runtime_template_ids = {"codex-safe"},
    };
    auto registry = path_exposure_registry::build({std::move(policy)});
    REQUIRE(registry.has_value());

    const auto source = protected_root / "source";
    const auto stage = temporary.root() / "stage";
    REQUIRE(std::filesystem::create_directory(source));
    REQUIRE(std::filesystem::create_directory(stage));
    std::ofstream{source / "file.txt"} << "before\n";
    std::ofstream{stage / "file.txt"} << "after\n";
    std::ofstream{stage / "created.txt"} << "created\n";
    auto exposure = registry->create(create_request(source, "request-a", "workspace-a"), 1'000);
    REQUIRE(exposure.has_value());
    auto manifest = manifest_for(source, stage, *exposure, "session-a", true);
    REQUIRE(manifest.has_value());
    auto reservation = reservation_for(*manifest, 'a');
    auto target = registry->resolve_recovery_target(
        exposure->exposure_id,
        exposure->generation,
        exposure->scope_digest,
        exposure->source_identity_digest
    );
    REQUIRE(target.has_value());
    descriptor staged{stage, true};
    REQUIRE(staged.get() >= 0);
    auto reserved_observation =
        inspect_change_apply_exchange_recovery(reservation, *manifest, *target);
    REQUIRE(reserved_observation.has_value());
    REQUIRE(reserved_observation->state == change_apply_recovery_state::reserved);
    REQUIRE(!reserved_observation->candidate_tree_digest.has_value());
    auto recovery_journal = change_apply_journal::open(temporary.root() / "recovery-apply.journal");
    REQUIRE(recovery_journal.has_value());
    REQUIRE(recovery_journal->reserve(reservation).has_value());
    auto applied = execute_change_apply_exchange(reservation, *manifest, *target, staged.get());
    if (!applied) {
        std::fprintf(stderr, "directory apply failed: %s\n", applied.error().c_str());
    }
    REQUIRE(applied.has_value());
    REQUIRE(applied->final_tree_digest == manifest->staged_tree_digest);
    REQUIRE(applied->final_source_identity_digest != exposure->source_identity_digest);
    REQUIRE(read_text(source / "file.txt") == "after\n");
    REQUIRE(read_text(source / "created.txt") == "created\n");
    const auto prior_path = protected_root / applied->candidate_name;
    REQUIRE(read_text(prior_path / "file.txt") == "before\n");
    auto committed_observation =
        inspect_change_apply_exchange_recovery(reservation, *manifest, *target);
    REQUIRE(committed_observation.has_value());
    REQUIRE(committed_observation->state == change_apply_recovery_state::exchange_committed);
    REQUIRE(committed_observation->candidate_tree_digest.has_value());
    descriptor installed{source, true};
    descriptor prior{prior_path, true};
    REQUIRE(installed.get() >= 0);
    REQUIRE(prior.get() >= 0);
    auto installed_snapshot = snapshot_path_tree(installed.get(), stage_bytes);
    auto prior_snapshot = snapshot_path_tree(prior.get(), stage_bytes);
    REQUIRE(installed_snapshot.has_value());
    REQUIRE(prior_snapshot.has_value());
    auto installed_digest = path_snapshot_digest(*installed_snapshot);
    auto prior_digest = path_snapshot_digest(*prior_snapshot);
    REQUIRE(installed_digest.has_value());
    REQUIRE(prior_digest.has_value());
    REQUIRE(
        classify_change_apply_recovery(reservation, *installed_digest, *prior_digest) ==
        change_apply_recovery_state::exchange_committed
    );
    auto recovered =
        finalize_committed_change_apply_recovery(*manifest, *target, 3'000, *recovery_journal);
    REQUIRE(recovered.has_value());
    REQUIRE(recovered->baseline_cleanup_complete);
    REQUIRE(!std::filesystem::exists(prior_path));
    const auto recovered_status = recovery_journal->find(reservation.grant_id);
    REQUIRE(recovered_status.has_value());
    REQUIRE(recovered_status->terminal.has_value());
    REQUIRE(recovered_status->terminal->receipt_digest == recovered->receipt.receipt_digest);
    auto reconstructed_recovery_receipt =
        reconstruct_change_apply_receipt(reservation, *recovered_status->terminal);
    REQUIRE(reconstructed_recovery_receipt.has_value());
    REQUIRE(*reconstructed_recovery_receipt == recovered->receipt);
    REQUIRE(
        !execute_change_apply_exchange(reservation, *manifest, *target, staged.get()).has_value()
    );

    const auto reserved_source = protected_root / "reserved-source.txt";
    const auto reserved_stage = temporary.root() / "reserved-stage.txt";
    std::ofstream{reserved_source} << "reserved baseline\n";
    std::ofstream{reserved_stage} << "reserved stage\n";
    auto reserved_exposure =
        registry->create(create_request(reserved_source, "request-r", "workspace-r"), 1'000);
    REQUIRE(reserved_exposure.has_value());
    auto reserved_manifest =
        manifest_for(reserved_source, reserved_stage, *reserved_exposure, "session-r", false);
    REQUIRE(reserved_manifest.has_value());
    auto reserved_record = reservation_for(*reserved_manifest, '6');
    auto reserved_target = registry->resolve_recovery_target(
        reserved_exposure->exposure_id,
        reserved_exposure->generation,
        reserved_exposure->scope_digest,
        reserved_exposure->source_identity_digest
    );
    REQUIRE(reserved_target.has_value());
    auto reserved_journal =
        change_apply_journal::open(temporary.root() / "reserved-recovery.journal");
    REQUIRE(reserved_journal.has_value());
    REQUIRE(reserved_journal->reserve(reserved_record).has_value());
    auto reserved_recovery = recover_pending_change_apply(
        *reserved_manifest, *reserved_target, 3'000, *reserved_journal
    );
    REQUIRE(reserved_recovery.has_value());
    REQUIRE(!reserved_recovery->exchange.has_value());
    REQUIRE(reserved_recovery->receipt.state == "failed");
    REQUIRE(reserved_recovery->receipt.failure_code == "interrupted_before_mutation");
    REQUIRE(reserved_recovery->baseline_cleanup_complete);
    const auto reserved_status = reserved_journal->find(reserved_record.grant_id);
    REQUIRE(reserved_status.has_value());
    REQUIRE(reserved_status->terminal.has_value());
    REQUIRE(reserved_status->terminal->state == change_apply_terminal_state::failed);
    auto reconstructed_reserved_receipt =
        reconstruct_change_apply_receipt(reserved_record, *reserved_status->terminal);
    REQUIRE(reconstructed_reserved_receipt.has_value());
    REQUIRE(*reconstructed_reserved_receipt == reserved_recovery->receipt);
    REQUIRE(read_text(reserved_source) == "reserved baseline\n");

    const auto sweep_source = protected_root / "sweep-source.txt";
    const auto sweep_stage = temporary.root() / "sweep-stage.txt";
    std::ofstream{sweep_source} << "sweep baseline\n";
    std::ofstream{sweep_stage} << "sweep stage\n";
    auto sweep_exposure =
        registry->create(create_request(sweep_source, "request-s", "workspace-s"), 1'000);
    REQUIRE(sweep_exposure.has_value());
    auto sweep_manifest =
        manifest_for(sweep_source, sweep_stage, *sweep_exposure, "session-s", false);
    REQUIRE(sweep_manifest.has_value());
    auto sweep_record = reservation_for(*sweep_manifest, '5');
    auto sweep_journal = change_apply_journal::open(temporary.root() / "sweep-recovery.journal");
    REQUIRE(sweep_journal.has_value());
    REQUIRE(sweep_journal->reserve(sweep_record).has_value());
    const auto sweep_materializations = temporary.root() / "sweep-materializations";
    REQUIRE(publish_file_stage(sweep_materializations, *sweep_manifest, sweep_stage));
    auto sweep_report = reconcile_change_apply_journal(
        sweep_materializations.string(), *registry, 3'000, *sweep_journal
    );
    REQUIRE(sweep_report.failed_finalized == 1U);
    REQUIRE(sweep_report.applied_finalized == 0U);
    REQUIRE(sweep_report.cleanup_completed == 1U);
    REQUIRE(sweep_report.unresolved == 0U);
    REQUIRE(sweep_report.issues.empty());
    const auto swept_status = sweep_journal->find(sweep_record.grant_id);
    REQUIRE(swept_status.has_value());
    REQUIRE(swept_status->terminal.has_value());
    REQUIRE(swept_status->terminal->state == change_apply_terminal_state::failed);
    auto repeated_sweep = reconcile_change_apply_journal(
        (temporary.root() / "missing-materializations").string(), *registry, 3'001, *sweep_journal
    );
    REQUIRE(repeated_sweep.failed_finalized == 0U);
    REQUIRE(repeated_sweep.unresolved == 0U);

    const auto prepared_source = protected_root / "prepared-source.txt";
    const auto prepared_stage = temporary.root() / "prepared-stage.txt";
    std::ofstream{prepared_source} << "prepared baseline\n";
    std::ofstream{prepared_stage} << "prepared stage\n";
    auto prepared_exposure =
        registry->create(create_request(prepared_source, "request-p", "workspace-p"), 1'000);
    REQUIRE(prepared_exposure.has_value());
    auto prepared_manifest =
        manifest_for(prepared_source, prepared_stage, *prepared_exposure, "session-p", false);
    REQUIRE(prepared_manifest.has_value());
    auto prepared_record = reservation_for(*prepared_manifest, '7');
    auto prepared_target = registry->resolve_recovery_target(
        prepared_exposure->exposure_id,
        prepared_exposure->generation,
        prepared_exposure->scope_digest,
        prepared_exposure->source_identity_digest
    );
    REQUIRE(prepared_target.has_value());
    auto prepared_name = change_apply_candidate_name(prepared_record.authorization_digest);
    REQUIRE(prepared_name.has_value());
    const auto prepared_candidate = protected_root / *prepared_name;
    REQUIRE(std::filesystem::copy_file(prepared_stage, prepared_candidate));
    auto prepared_observation = inspect_change_apply_exchange_recovery(
        prepared_record, *prepared_manifest, *prepared_target
    );
    REQUIRE(prepared_observation.has_value());
    REQUIRE(prepared_observation->state == change_apply_recovery_state::candidate_prepared);
    auto prepared_journal =
        change_apply_journal::open(temporary.root() / "prepared-recovery.journal");
    REQUIRE(prepared_journal.has_value());
    REQUIRE(prepared_journal->reserve(prepared_record).has_value());
    auto prepared_recovery = recover_pending_change_apply(
        *prepared_manifest, *prepared_target, 3'000, *prepared_journal
    );
    REQUIRE(prepared_recovery.has_value());
    REQUIRE(!prepared_recovery->exchange.has_value());
    REQUIRE(prepared_recovery->receipt.state == "failed");
    REQUIRE(!std::filesystem::exists(prepared_candidate));
    REQUIRE(read_text(prepared_source) == "prepared baseline\n");
    const auto prepared_status = prepared_journal->find(prepared_record.grant_id);
    REQUIRE(prepared_status.has_value());
    REQUIRE(prepared_status->terminal.has_value());
    REQUIRE(prepared_status->terminal->state == change_apply_terminal_state::failed);
    auto reconstructed_prepared_receipt =
        reconstruct_change_apply_receipt(prepared_record, *prepared_status->terminal);
    REQUIRE(reconstructed_prepared_receipt.has_value());
    REQUIRE(*reconstructed_prepared_receipt == prepared_recovery->receipt);

    const auto ambiguous_source = protected_root / "ambiguous-source.txt";
    const auto ambiguous_stage = temporary.root() / "ambiguous-stage.txt";
    std::ofstream{ambiguous_source} << "ambiguous baseline\n";
    std::ofstream{ambiguous_stage} << "ambiguous stage\n";
    auto ambiguous_exposure =
        registry->create(create_request(ambiguous_source, "request-u", "workspace-u"), 1'000);
    REQUIRE(ambiguous_exposure.has_value());
    auto ambiguous_manifest =
        manifest_for(ambiguous_source, ambiguous_stage, *ambiguous_exposure, "session-u", false);
    REQUIRE(ambiguous_manifest.has_value());
    auto ambiguous_record = reservation_for(*ambiguous_manifest, '8');
    auto ambiguous_target = registry->resolve_recovery_target(
        ambiguous_exposure->exposure_id,
        ambiguous_exposure->generation,
        ambiguous_exposure->scope_digest,
        ambiguous_exposure->source_identity_digest
    );
    REQUIRE(ambiguous_target.has_value());
    auto ambiguous_journal =
        change_apply_journal::open(temporary.root() / "ambiguous-recovery.journal");
    REQUIRE(ambiguous_journal.has_value());
    REQUIRE(ambiguous_journal->reserve(ambiguous_record).has_value());
    std::ofstream{ambiguous_source} << "unclassified concurrent mutation\n";
    REQUIRE(!recover_pending_change_apply(
                 *ambiguous_manifest, *ambiguous_target, 3'000, *ambiguous_journal
    )
                 .has_value());
    const auto ambiguous_status = ambiguous_journal->find(ambiguous_record.grant_id);
    REQUIRE(ambiguous_status.has_value());
    REQUIRE(!ambiguous_status->terminal.has_value());
    REQUIRE(read_text(ambiguous_source) == "unclassified concurrent mutation\n");

    const auto cleanup_source = protected_root / "cleanup-source.txt";
    const auto cleanup_stage = temporary.root() / "cleanup-stage.txt";
    std::ofstream{cleanup_source} << "cleanup baseline\n";
    std::ofstream{cleanup_stage} << "cleanup stage\n";
    auto cleanup_exposure =
        registry->create(create_request(cleanup_source, "request-x", "workspace-x"), 1'000);
    REQUIRE(cleanup_exposure.has_value());
    auto cleanup_manifest =
        manifest_for(cleanup_source, cleanup_stage, *cleanup_exposure, "session-x", false);
    REQUIRE(cleanup_manifest.has_value());
    auto cleanup_record = reservation_for(*cleanup_manifest, '9');
    auto cleanup_target = registry->resolve_recovery_target(
        cleanup_exposure->exposure_id,
        cleanup_exposure->generation,
        cleanup_exposure->scope_digest,
        cleanup_exposure->source_identity_digest
    );
    REQUIRE(cleanup_target.has_value());
    descriptor cleanup_staged{cleanup_stage, false};
    REQUIRE(cleanup_staged.get() >= 0);
    auto cleanup_journal =
        change_apply_journal::open(temporary.root() / "cleanup-recovery.journal");
    REQUIRE(cleanup_journal.has_value());
    REQUIRE(cleanup_journal->reserve(cleanup_record).has_value());
    auto cleanup_exchange = execute_change_apply_exchange(
        cleanup_record, *cleanup_manifest, *cleanup_target, cleanup_staged.get()
    );
    REQUIRE(cleanup_exchange.has_value());
    const auto cleanup_candidate = protected_root / cleanup_exchange->candidate_name;
    constexpr std::string_view cleanup_xattr_value = "blocks-cleanup";
    REQUIRE(
        ::setxattr(
            cleanup_candidate.c_str(),
            "user.glove-cleanup-test",
            cleanup_xattr_value.data(),
            cleanup_xattr_value.size(),
            0
        ) == 0
    );
    auto cleanup_recovery = finalize_committed_change_apply_recovery(
        *cleanup_manifest, *cleanup_target, 3'000, *cleanup_journal
    );
    REQUIRE(cleanup_recovery.has_value());
    REQUIRE(!cleanup_recovery->baseline_cleanup_complete);
    REQUIRE(std::filesystem::exists(cleanup_candidate));
    const auto cleanup_status = cleanup_journal->find(cleanup_record.grant_id);
    REQUIRE(cleanup_status.has_value());
    REQUIRE(cleanup_status->terminal.has_value());
    REQUIRE(cleanup_status->terminal->state == change_apply_terminal_state::applied);
    REQUIRE(::removexattr(cleanup_candidate.c_str(), "user.glove-cleanup-test") == 0);
    REQUIRE(cleanup_finalized_change_apply_baseline(
                cleanup_record, *cleanup_status->terminal, *cleanup_manifest, *cleanup_target
    )
                .has_value());
    REQUIRE(!std::filesystem::exists(cleanup_candidate));

    const auto stale_source = protected_root / "stale-source";
    const auto stale_stage = temporary.root() / "stale-stage";
    REQUIRE(std::filesystem::create_directory(stale_source));
    REQUIRE(std::filesystem::create_directory(stale_stage));
    std::ofstream{stale_source / "file.txt"} << "baseline\n";
    std::ofstream{stale_stage / "file.txt"} << "approved\n";
    auto stale_exposure =
        registry->create(create_request(stale_source, "request-b", "workspace-b"), 1'000);
    REQUIRE(stale_exposure.has_value());
    auto stale_manifest =
        manifest_for(stale_source, stale_stage, *stale_exposure, "session-b", true);
    REQUIRE(stale_manifest.has_value());
    auto stale_reservation = reservation_for(*stale_manifest, 'b');
    auto stale_target = registry->resolve_recovery_target(
        stale_exposure->exposure_id,
        stale_exposure->generation,
        stale_exposure->scope_digest,
        stale_exposure->source_identity_digest
    );
    REQUIRE(stale_target.has_value());
    std::ofstream{stale_source / "file.txt"} << "concurrent host edit\n";
    descriptor stale_staged{stale_stage, true};
    REQUIRE(stale_staged.get() >= 0);
    REQUIRE(!execute_change_apply_exchange(
                 stale_reservation, *stale_manifest, *stale_target, stale_staged.get()
    )
                 .has_value());
    auto stale_candidate = change_apply_candidate_name(stale_reservation.authorization_digest);
    REQUIRE(stale_candidate.has_value());
    REQUIRE(!std::filesystem::exists(protected_root / *stale_candidate));
    REQUIRE(read_text(stale_source / "file.txt") == "concurrent host edit\n");

    const auto file_source = protected_root / "single.txt";
    const auto file_stage = temporary.root() / "single-stage.txt";
    std::ofstream{file_source} << "old file\n";
    std::ofstream{file_stage} << "new file\n";
    auto file_exposure =
        registry->create(create_request(file_source, "request-c", "workspace-c"), 1'000);
    REQUIRE(file_exposure.has_value());
    auto file_manifest = manifest_for(file_source, file_stage, *file_exposure, "session-c", false);
    REQUIRE(file_manifest.has_value());
    auto file_target = registry->resolve_recovery_target(
        file_exposure->exposure_id,
        file_exposure->generation,
        file_exposure->scope_digest,
        file_exposure->source_identity_digest
    );
    REQUIRE(file_target.has_value());
    descriptor file_staged{file_stage, false};
    REQUIRE(file_staged.get() >= 0);
    auto file_authorization = authorization_for(*file_manifest, "grant-c");
    REQUIRE(file_authorization.has_value());
    auto apply_journal = change_apply_journal::open(temporary.root() / "authorized-apply.journal");
    REQUIRE(apply_journal.has_value());
    accepting_verifier verifier;
    auto file_applied = execute_authorized_change_apply(
        file_authorization->authorization.canonical_json,
        file_authorization->context,
        *file_manifest,
        *file_target,
        file_staged.get(),
        2'000,
        verifier,
        *apply_journal
    );
    if (!file_applied) {
        std::fprintf(stderr, "file apply failed: %s\n", file_applied.error().c_str());
    }
    REQUIRE(file_applied.has_value());
    REQUIRE(read_text(file_source) == "new file\n");
    REQUIRE(file_applied->baseline_cleanup_complete);
    REQUIRE(file_applied->exchange.has_value());
    REQUIRE(!std::filesystem::exists(protected_root / file_applied->exchange->candidate_name));
    REQUIRE(
        file_applied->receipt.authorization_digest ==
        file_authorization->authorization.authorization_digest
    );
    const auto terminal = apply_journal->find("grant-c");
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->terminal.has_value());
    REQUIRE(terminal->terminal->receipt_digest == file_applied->receipt.receipt_digest);
    REQUIRE(!execute_authorized_change_apply(
                 file_authorization->authorization.canonical_json,
                 file_authorization->context,
                 *file_manifest,
                 *file_target,
                 file_staged.get(),
                 2'001,
                 verifier,
                 *apply_journal
    )
                 .has_value());

    const auto metadata_source = protected_root / "metadata-source.txt";
    const auto metadata_stage = temporary.root() / "metadata-stage.txt";
    std::ofstream{metadata_source} << "baseline metadata\n";
    std::ofstream{metadata_stage} << "staged metadata\n";
    auto metadata_exposure =
        registry->create(create_request(metadata_source, "request-d", "workspace-d"), 1'000);
    REQUIRE(metadata_exposure.has_value());
    auto metadata_manifest =
        manifest_for(metadata_source, metadata_stage, *metadata_exposure, "session-d", false);
    REQUIRE(metadata_manifest.has_value());
    auto metadata_target = registry->resolve_recovery_target(
        metadata_exposure->exposure_id,
        metadata_exposure->generation,
        metadata_exposure->scope_digest,
        metadata_exposure->source_identity_digest
    );
    REQUIRE(metadata_target.has_value());
    auto metadata_authorization = authorization_for(*metadata_manifest, "grant-d");
    REQUIRE(metadata_authorization.has_value());
    descriptor metadata_staged{metadata_stage, false};
    REQUIRE(metadata_staged.get() >= 0);
    constexpr std::string_view xattr_value = "not-in-manifest";
    REQUIRE(
        ::setxattr(
            metadata_stage.c_str(), "user.glove-test", xattr_value.data(), xattr_value.size(), 0
        ) == 0
    );
    auto metadata_journal = change_apply_journal::open(temporary.root() / "metadata-apply.journal");
    REQUIRE(metadata_journal.has_value());
    REQUIRE(!execute_authorized_change_apply(
                 metadata_authorization->authorization.canonical_json,
                 metadata_authorization->context,
                 *metadata_manifest,
                 *metadata_target,
                 metadata_staged.get(),
                 2'000,
                 verifier,
                 *metadata_journal
    )
                 .has_value());
    REQUIRE(metadata_journal->records().empty());
    REQUIRE(read_text(metadata_source) == "baseline metadata\n");

    const auto boundary_source = protected_root / "boundary-source.txt";
    const auto boundary_stage = temporary.root() / "boundary-stage.txt";
    std::ofstream{boundary_source} << "baseline boundary\n";
    std::ofstream{boundary_stage} << "staged boundary\n";
    auto boundary_exposure =
        registry->create(create_request(boundary_source, "request-e", "workspace-e"), 1'000);
    REQUIRE(boundary_exposure.has_value());
    auto boundary_manifest =
        manifest_for(boundary_source, boundary_stage, *boundary_exposure, "session-e", false);
    REQUIRE(boundary_manifest.has_value());
    auto boundary_target = registry->resolve_recovery_target(
        boundary_exposure->exposure_id,
        boundary_exposure->generation,
        boundary_exposure->scope_digest,
        boundary_exposure->source_identity_digest
    );
    REQUIRE(boundary_target.has_value());
    auto boundary_authorization = authorization_for(*boundary_manifest, "grant-e");
    REQUIRE(boundary_authorization.has_value());
    descriptor boundary_staged{boundary_stage, false};
    REQUIRE(boundary_staged.get() >= 0);
    auto boundary_journal = change_apply_journal::open(temporary.root() / "boundary-apply.journal");
    REQUIRE(boundary_journal.has_value());
    REQUIRE(::chmod(protected_root.c_str(), 0775) == 0);
    REQUIRE(!execute_authorized_change_apply(
                 boundary_authorization->authorization.canonical_json,
                 boundary_authorization->context,
                 *boundary_manifest,
                 *boundary_target,
                 boundary_staged.get(),
                 2'000,
                 verifier,
                 *boundary_journal
    )
                 .has_value());
    REQUIRE(boundary_journal->records().empty());
    REQUIRE(read_text(boundary_source) == "baseline boundary\n");
    REQUIRE(::chmod(protected_root.c_str(), 0755) == 0);
    return 0;
#endif
}

} // namespace

auto main() -> int {
    return run();
}
