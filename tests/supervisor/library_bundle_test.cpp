#include "glove/container/digest.hpp"
#include "glove/supervisor/library_bundle.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-library-bundle-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto digest_for(std::string_view value) -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    return glove::container::sha256_hex(std::span{bytes, value.size()}).value_or("");
}

auto write_bundle(const std::filesystem::path& root, std::string_view contents, mode_t mode = 0600)
    -> std::filesystem::path {
    const auto path = root / (digest_for(contents) + ".json");
    {
        std::ofstream output{path, std::ios::binary | std::ios::trunc};
        output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }
    static_cast<void>(::chmod(path.c_str(), mode));
    return path;
}

auto read_descriptor(int descriptor, std::size_t size) -> std::string {
    std::string contents(size, '\0');
    const auto count = ::pread(descriptor, contents.data(), contents.size(), 0);
    if (count != static_cast<ssize_t>(contents.size())) {
        return {};
    }
    return contents;
}

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto root = temporary.root() / "bundles";
    REQUIRE(std::filesystem::create_directory(root));
    REQUIRE(::chmod(root.c_str(), 0700) == 0);

    constexpr std::string_view canonical =
        R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";
    const auto digest = digest_for(canonical);
    REQUIRE(digest.size() == 64U);
    const auto bundle_path = write_bundle(root, canonical);

    auto store = glove::supervisor::library_bundle_store::open(root);
    REQUIRE(store.has_value());
    auto resolved = store->resolve(digest);
    REQUIRE(resolved.has_value());
    REQUIRE(resolved->content_digest() == digest);
    REQUIRE(resolved->size_bytes() == canonical.size());
    REQUIRE(read_descriptor(resolved->descriptor_fd(), canonical.size()) == canonical);
    REQUIRE(resolved->verify_identity().has_value());

    std::vector<glove::supervisor::resolved_library_projection_target> targets;
    targets.push_back({
        .projection =
            {
                .projection_id = "sage-core",
                .content_digest = digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    auto projections = store->resolve_projections(targets);
    REQUIRE(projections.has_value());
    REQUIRE(projections->size() == 1U);
    REQUIRE(projections->front().projection_id == "sage-core");
    REQUIRE(projections->front().destination_alias == "libraries");
    REQUIRE(projections->front().target_path == "/opt/sage/library-bundles/" + digest + ".json");
    REQUIRE(projections->front().bundle.content_digest() == digest);
    REQUIRE(projections->front().bundle.verify_identity().has_value());

    auto duplicate_targets = targets;
    duplicate_targets.push_back({
        .projection =
            {
                .projection_id = "sage-duplicate",
                .content_digest = digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    REQUIRE(!store->resolve_projections(duplicate_targets).has_value());

    auto unavailable_targets = targets;
    unavailable_targets.front().projection.content_digest = std::string(64U, 'f');
    REQUIRE(!store->resolve_projections(unavailable_targets).has_value());

    REQUIRE(!store->resolve(std::string(64U, 'A')).has_value());
    REQUIRE(!store->resolve(std::string(63U, 'a')).has_value());
    REQUIRE(!glove::supervisor::library_bundle_store::open("relative/bundles").has_value());

    const auto unsafe_root = temporary.root() / "unsafe";
    REQUIRE(std::filesystem::create_directory(unsafe_root));
    REQUIRE(::chmod(unsafe_root.c_str(), 0755) == 0);
    REQUIRE(!glove::supervisor::library_bundle_store::open(unsafe_root).has_value());

    const auto symlink_root = temporary.root() / "bundle-link";
    REQUIRE(::symlink(root.c_str(), symlink_root.c_str()) == 0);
    REQUIRE(!glove::supervisor::library_bundle_store::open(symlink_root).has_value());

    constexpr std::string_view loose = R"({"schema_version":1,"entries":["loose"]})";
    const auto loose_path = write_bundle(root, loose, 0644);
    REQUIRE(!store->resolve(digest_for(loose)).has_value());

    constexpr std::string_view linked = R"({"schema_version":1,"entries":["linked"]})";
    const auto linked_path = write_bundle(root, linked);
    const auto second_link = temporary.root() / "second-link.json";
    REQUIRE(::link(linked_path.c_str(), second_link.c_str()) == 0);
    REQUIRE(!store->resolve(digest_for(linked)).has_value());

    constexpr std::string_view redirected = R"({"schema_version":1,"entries":["redirected"]})";
    const auto redirected_digest = digest_for(redirected);
    const auto outside = write_bundle(temporary.root(), redirected);
    const auto redirected_path = root / (redirected_digest + ".json");
    REQUIRE(::symlink(outside.c_str(), redirected_path.c_str()) == 0);
    REQUIRE(!store->resolve(redirected_digest).has_value());

    constexpr std::string_view expected = R"({"schema_version":1,"entries":["expected"]})";
    constexpr std::string_view corrupted = R"({"schema_version":1,"entries":["corrupt!"]})";
    REQUIRE(expected.size() == corrupted.size());
    const auto expected_digest = digest_for(expected);
    const auto corrupted_path = root / (expected_digest + ".json");
    {
        std::ofstream output{corrupted_path, std::ios::binary | std::ios::trunc};
        output.write(corrupted.data(), static_cast<std::streamsize>(corrupted.size()));
    }
    REQUIRE(::chmod(corrupted_path.c_str(), 0600) == 0);
    REQUIRE(!store->resolve(expected_digest).has_value());

    constexpr std::string_view mutable_bundle = R"({"schema_version":1,"entries":["mutable-a"]})";
    constexpr std::string_view changed_bundle = R"({"schema_version":1,"entries":["mutable-b"]})";
    REQUIRE(mutable_bundle.size() == changed_bundle.size());
    const auto mutable_path = write_bundle(root, mutable_bundle);
    auto mutable_resolved = store->resolve(digest_for(mutable_bundle));
    REQUIRE(mutable_resolved.has_value());
    {
        std::ofstream output{mutable_path, std::ios::binary | std::ios::trunc};
        output.write(changed_bundle.data(), static_cast<std::streamsize>(changed_bundle.size()));
    }
    REQUIRE(::chmod(mutable_path.c_str(), 0600) == 0);
    REQUIRE(!mutable_resolved->verify_identity().has_value());

    REQUIRE(::chmod(bundle_path.c_str(), 0400) == 0);
    REQUIRE(!resolved->verify_identity().has_value());

    REQUIRE(::chmod(root.c_str(), 0755) == 0);
    REQUIRE(!store->resolve(digest).has_value());
    REQUIRE(::chmod(root.c_str(), 0700) == 0);

    const auto original_root = temporary.root() / "original-bundles";
    std::filesystem::rename(root, original_root);
    REQUIRE(std::filesystem::is_directory(original_root));
    REQUIRE(std::filesystem::create_directory(root));
    REQUIRE(::chmod(root.c_str(), 0700) == 0);
    REQUIRE(!store->resolve(digest).has_value());

    static_cast<void>(loose_path);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
