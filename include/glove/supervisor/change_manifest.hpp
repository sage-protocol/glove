#pragma once

#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

struct path_snapshot_entry {
    std::string path;
    std::string content_digest;
    std::uint64_t bytes = 0;
    std::uint32_t mode = 0;
    bool directory = false;

    auto operator==(const path_snapshot_entry&) const -> bool = default;
};

enum class path_change_kind : std::uint8_t {
    create,
    modify,
    rename,
    remove,
};

struct path_change_entry {
    path_change_kind kind = path_change_kind::create;
    std::string path;
    std::string previous_path;
    std::string before_digest;
    std::string after_digest;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::uint32_t before_mode = 0;
    std::uint32_t after_mode = 0;
    bool directory = false;

    auto operator==(const path_change_entry&) const -> bool = default;
};

struct retained_change_manifest {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::uint64_t max_bytes = 0;
    bool directory = false;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::vector<path_change_entry> changes;
    std::uint64_t created = 0;
    std::uint64_t modified = 0;
    std::uint64_t renamed = 0;
    std::uint64_t removed = 0;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::string manifest_digest;
    std::string canonical_json;

    auto operator==(const retained_change_manifest&) const -> bool = default;
};

// Snapshot a descriptor-pinned regular file or directory without following
// symlinks. Both collection size and total regular-file bytes are bounded.
[[nodiscard]] auto
snapshot_path_tree(int descriptor, std::uint64_t max_bytes, std::size_t max_entries = 100'000U)
    -> result<std::vector<path_snapshot_entry>>;

[[nodiscard]] auto path_snapshot_digest(const std::vector<path_snapshot_entry>& snapshot)
    -> result<std::string>;

// Build a deterministic, digest-bound manifest. Rename inference is limited
// to unique exact-content matches; ambiguous matches remain remove/create.
[[nodiscard]] auto build_retained_change_manifest(
    std::string session_id,
    std::string exposure_id,
    std::uint64_t generation,
    std::string scope_digest,
    std::string source_identity_digest,
    std::uint64_t max_bytes,
    const std::vector<path_snapshot_entry>& baseline,
    const std::vector<path_snapshot_entry>& current
) -> result<retained_change_manifest>;

[[nodiscard]] auto decode_retained_change_manifest_json(std::string_view canonical_json)
    -> result<retained_change_manifest>;

// Open one published retained stage beneath the owner-only Glove state root,
// decode its canonical manifest, and recompute the staged tree digest through
// no-follow descriptors. Raw host paths are neither accepted nor returned.
[[nodiscard]] auto inspect_retained_change_stage(
    std::string_view materialization_root, std::string_view session_id, std::string_view exposure_id
) -> result<retained_change_manifest>;

} // namespace glove::supervisor
