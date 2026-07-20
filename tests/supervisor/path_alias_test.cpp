#include "glove/supervisor/path_alias.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern = "/tmp/glove-path-alias-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = std::filesystem::canonical(created);
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;

    ~temporary_tree() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto read_mode() -> glove::supervisor::path_access_policy {
    return {
        .access = glove::supervisor::path_access::read,
        .materialization = glove::supervisor::path_materialization::bind,
        .create_policy = glove::supervisor::path_create_policy::never,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
        .max_bytes = 0,
    };
}

auto ephemeral_mode() -> glove::supervisor::path_access_policy {
    return {
        .access = glove::supervisor::path_access::ephemeral_write,
        .materialization = glove::supervisor::path_materialization::copy,
        .create_policy = glove::supervisor::path_create_policy::empty_directory,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::remove,
        .max_bytes = 1024U * 1024U,
    };
}

auto direct_mode() -> glove::supervisor::path_access_policy {
    return {
        .access = glove::supervisor::path_access::direct_write,
        .materialization = glove::supervisor::path_materialization::bind,
        .create_policy = glove::supervisor::path_create_policy::never,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
        .max_bytes = 0,
    };
}

auto policy_for(const std::filesystem::path& host_path) -> glove::supervisor::path_alias_policy {
    return {
        .alias = "sage_protocol",
        .host_path = host_path.string(),
        .target_path = "/workspace/sage-protocol",
        .max_ttl_secs = 3600,
        .access = {read_mode(), ephemeral_mode(), direct_mode()},
    };
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(!tree.root().empty());
    const auto source = tree.root() / "source";
    const auto replacement = tree.root() / "replacement";
    REQUIRE(std::filesystem::create_directory(source));
    REQUIRE(std::filesystem::create_directory(replacement));
    {
        std::ofstream marker{source / "marker"};
        marker << "original";
    }

    auto registry = glove::supervisor::path_alias_registry::build({policy_for(source)});
    REQUIRE(registry.has_value());

    const glove::supervisor::path_grant_request read_request{
        .alias = "sage_protocol",
        .access = glove::supervisor::path_access::read,
        .ttl_secs = 60,
        .max_bytes = 0,
    };
    auto read_grant = registry->resolve(read_request);
    REQUIRE(read_grant.has_value());
    REQUIRE(read_grant->descriptor_fd() >= 0);
    REQUIRE(read_grant->alias() == "sage_protocol");
    REQUIRE(read_grant->target_path() == "/workspace/sage-protocol");
    REQUIRE(read_grant->access() == glove::supervisor::path_access::read);
    REQUIRE(read_grant->materialization() == glove::supervisor::path_materialization::bind);
    REQUIRE(read_grant->ttl_secs() == 60);
    REQUIRE(read_grant->max_bytes() == 0);
    REQUIRE(read_grant->identity().inode != 0);
    REQUIRE(read_grant->verify_identity().has_value());

    auto unknown = registry->resolve({
        .alias = "not_configured",
        .access = glove::supervisor::path_access::read,
        .ttl_secs = 60,
    });
    REQUIRE(!unknown.has_value());
    auto raw_path = registry->resolve({
        .alias = source.string(),
        .access = glove::supervisor::path_access::read,
        .ttl_secs = 60,
    });
    REQUIRE(!raw_path.has_value());
    auto excessive_ttl = registry->resolve({
        .alias = "sage_protocol",
        .access = glove::supervisor::path_access::read,
        .ttl_secs = 3601,
    });
    REQUIRE(!excessive_ttl.has_value());

    auto ephemeral = registry->resolve({
        .alias = "sage_protocol",
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 120,
        .max_bytes = 512U * 1024U,
    });
    REQUIRE(ephemeral.has_value());
    REQUIRE(ephemeral->materialization() == glove::supervisor::path_materialization::copy);
    REQUIRE(ephemeral->cleanup_policy() == glove::supervisor::path_cleanup_policy::remove);
    REQUIRE(ephemeral->max_bytes() == 512U * 1024U);
    auto unbounded = registry->resolve({
        .alias = "sage_protocol",
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 120,
        .max_bytes = 0,
    });
    REQUIRE(!unbounded.has_value());
    auto excessive_quota = registry->resolve({
        .alias = "sage_protocol",
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 120,
        .max_bytes = 2U * 1024U * 1024U,
    });
    REQUIRE(!excessive_quota.has_value());
    auto direct = registry->resolve({
        .alias = "sage_protocol",
        .access = glove::supervisor::path_access::direct_write,
        .ttl_secs = 120,
    });
    REQUIRE(!direct.has_value());
    REQUIRE(direct.error().find("authenticated local approval") != std::string::npos);
    REQUIRE(registry
                ->validate_plan({
                    .grant =
                        {
                            .alias = "sage_protocol",
                            .access = glove::supervisor::path_access::direct_write,
                            .ttl_secs = 120,
                        },
                    .materialization = glove::supervisor::path_materialization::bind,
                    .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
                })
                .has_value());
    REQUIRE(!registry
                 ->validate_plan({
                     .grant =
                         {
                             .alias = "sage_protocol",
                             .access = glove::supervisor::path_access::direct_write,
                             .ttl_secs = 120,
                         },
                     .materialization = glove::supervisor::path_materialization::copy,
                     .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
                 })
                 .has_value());

    auto duplicate_alias =
        glove::supervisor::path_alias_registry::build({policy_for(source), policy_for(source)});
    REQUIRE(!duplicate_alias.has_value());
    const auto nested_source = source / "nested";
    REQUIRE(std::filesystem::create_directory(nested_source));
    auto nested_policy = policy_for(nested_source);
    nested_policy.alias = "nested";
    nested_policy.target_path = "/workspace/nested";
    REQUIRE(!glove::supervisor::path_alias_registry::build({policy_for(source),
                                                            std::move(nested_policy)})
                 .has_value());
    auto overlapping_target = policy_for(replacement);
    overlapping_target.alias = "replacement";
    overlapping_target.target_path = "/workspace/sage-protocol/nested";
    REQUIRE(!glove::supervisor::path_alias_registry::build({policy_for(source),
                                                            std::move(overlapping_target)})
                 .has_value());
    auto duplicate_access_policy = policy_for(source);
    duplicate_access_policy.access.push_back(read_mode());
    REQUIRE(!glove::supervisor::path_alias_registry::build({std::move(duplicate_access_policy)})
                 .has_value());
    auto traversal_policy = policy_for(source);
    traversal_policy.alias = "../escape";
    REQUIRE(
        !glove::supervisor::path_alias_registry::build({std::move(traversal_policy)}).has_value()
    );
    auto target_traversal = policy_for(source);
    target_traversal.target_path = "/workspace/../etc";
    REQUIRE(
        !glove::supervisor::path_alias_registry::build({std::move(target_traversal)}).has_value()
    );
    auto reserved = policy_for(source);
    reserved.target_path = "/proc/agent";
    REQUIRE(!glove::supervisor::path_alias_registry::build({std::move(reserved)}).has_value());
    auto host_root = policy_for("/");
    REQUIRE(!glove::supervisor::path_alias_registry::build({std::move(host_root)}).has_value());
    auto host_home = policy_for("/home/example");
    REQUIRE(!glove::supervisor::path_alias_registry::build({std::move(host_home)}).has_value());
    auto host_proc = policy_for("/proc/version");
    REQUIRE(!glove::supervisor::path_alias_registry::build({std::move(host_proc)}).has_value());
    auto host_secret = policy_for("/srv/.ssh/keys");
    REQUIRE(!glove::supervisor::path_alias_registry::build({std::move(host_secret)}).has_value());

    const auto fifo_source = tree.root() / "fifo-source";
    REQUIRE(::mkfifo(fifo_source.c_str(), 0600) == 0);
    REQUIRE(!glove::supervisor::path_alias_registry::build({policy_for(fifo_source)}).has_value());

    const auto file_source = tree.root() / "file-source";
    const auto hardlink_source = tree.root() / "hardlink-source";
    {
        std::ofstream file{file_source};
        file << "same inode";
    }
    REQUIRE(::link(file_source.c_str(), hardlink_source.c_str()) == 0);
    auto hardlink_policy = policy_for(hardlink_source);
    hardlink_policy.alias = "hardlink";
    hardlink_policy.target_path = "/workspace/hardlink";
    REQUIRE(!glove::supervisor::path_alias_registry::build({policy_for(file_source),
                                                            std::move(hardlink_policy)})
                 .has_value());

    const auto symlink_source = tree.root() / "symlink-source";
    REQUIRE(::symlink(source.c_str(), symlink_source.c_str()) == 0);
    auto symlink_registry =
        glove::supervisor::path_alias_registry::build({policy_for(symlink_source)});
    REQUIRE(!symlink_registry.has_value());

    const auto original_location = tree.root() / "source-original";
    std::filesystem::rename(source, original_location);
    std::filesystem::rename(replacement, source);
    REQUIRE(!read_grant->verify_identity().has_value());
    auto replacement_grant = registry->resolve(read_request);
    REQUIRE(replacement_grant.has_value());
    REQUIRE(replacement_grant->identity() != read_grant->identity());

    std::filesystem::remove_all(source);
    REQUIRE(::symlink(original_location.c_str(), source.c_str()) == 0);
    REQUIRE(!registry->resolve(read_request).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
