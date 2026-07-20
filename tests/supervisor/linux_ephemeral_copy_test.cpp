#include "glove/supervisor/linux_ephemeral_copy.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

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
        std::string pattern = "/tmp/glove-materialization-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
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

auto access_policy(std::uint64_t max_bytes) -> glove::supervisor::path_access_policy {
    return {
        .access = glove::supervisor::path_access::ephemeral_write,
        .materialization = glove::supervisor::path_materialization::copy,
        .create_policy = glove::supervisor::path_create_policy::empty_directory,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::remove,
        .max_bytes = max_bytes,
    };
}

auto policy_for(
    std::string alias,
    const std::filesystem::path& source,
    std::string target,
    std::uint64_t max_bytes
) -> glove::supervisor::path_alias_policy {
    return {
        .alias = std::move(alias),
        .host_path = source.string(),
        .target_path = std::move(target),
        .max_ttl_secs = 3600,
        .access = {access_policy(max_bytes)},
    };
}

auto count_entries(const std::filesystem::path& path) -> std::size_t {
    return static_cast<std::size_t>(std::distance(
        std::filesystem::directory_iterator{path}, std::filesystem::directory_iterator{}
    ));
}

auto read_at(int directory_fd, const char* name) -> std::string {
    const int fd = ::openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return {};
    }
    std::array<char, 256> buffer{};
    const ::ssize_t count = ::read(fd, buffer.data(), buffer.size());
    ::close(fd);
    return count > 0 ? std::string{buffer.data(), static_cast<std::size_t>(count)} : std::string{};
}

auto quota_is_enforced(int directory_fd, std::uint64_t quota_bytes) -> bool {
    const int fd = ::openat(
        directory_fd, "quota-pressure", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    );
    if (fd < 0) {
        return errno == ENOSPC || errno == EDQUOT;
    }
    std::array<char, 4096> block{};
    bool denied = false;
    const auto attempts = quota_bytes / block.size() + 16;
    for (std::uint64_t attempt = 0; attempt < attempts; ++attempt) {
        const ::ssize_t written = ::write(fd, block.data(), block.size());
        if (written < 0) {
            denied = errno == ENOSPC || errno == EDQUOT;
            break;
        }
    }
    ::close(fd);
    return denied;
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(!tree.root().empty());
    const auto materialization_root = tree.root() / "materializations";
    const auto source = tree.root() / "source";
    REQUIRE(std::filesystem::create_directory(materialization_root));
    REQUIRE(::chmod(materialization_root.c_str(), 0700) == 0);
    REQUIRE(std::filesystem::create_directory(source));
    REQUIRE(std::filesystem::create_directory(source / "nested"));
    {
        std::ofstream alpha{source / "alpha.txt"};
        alpha << "alpha";
        std::ofstream beta{source / "nested" / "beta.txt"};
        beta << "beta";
    }

    const long page_size = ::sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    const auto page_bytes = static_cast<std::uint64_t>(page_size);
    const std::uint64_t quota_bytes = page_bytes * 16U;
    auto registry = glove::supervisor::path_alias_registry::build(
        {policy_for("workspace", source, "/workspace/project", quota_bytes)}
    );
    REQUIRE(registry.has_value());
    auto grant = registry->resolve({
        .alias = "workspace",
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 300,
        .max_bytes = quota_bytes,
    });
    REQUIRE(grant.has_value());

    auto materialized = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-1", *grant
    );
    if (!materialized &&
        materialized.error().find("tmpfs mount unavailable") != std::string::npos) {
        std::fprintf(stderr, "%s\n", materialized.error().c_str());
        return 77;
    }
    REQUIRE(materialized.has_value());
    REQUIRE(materialized->content_fd() >= 0);
    REQUIRE(materialized->is_directory());
    REQUIRE(materialized->alias() == "workspace");
    REQUIRE(materialized->target_path() == "/workspace/project");
    REQUIRE(read_at(materialized->content_fd(), "alpha.txt") == "alpha");
    const int nested = ::openat(
        materialized->content_fd(), "nested", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    REQUIRE(nested >= 0);
    REQUIRE(read_at(nested, "beta.txt") == "beta");
    ::close(nested);
    auto usage = materialized->observe();
    REQUIRE(usage.has_value());
    REQUIRE(usage->logical_bytes == 9);
    REQUIRE(usage->quota_bytes == quota_bytes);
    REQUIRE(usage->regular_files == 2);
    REQUIRE(usage->directories == 2);

    auto duplicate = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-1", *grant
    );
    REQUIRE(!duplicate.has_value());
    REQUIRE(quota_is_enforced(materialized->content_fd(), quota_bytes));
    REQUIRE(materialized->cleanup().has_value());
    REQUIRE(count_entries(materialization_root) == 0);

    auto reusable = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-1", *grant
    );
    REQUIRE(reusable.has_value());
    const int live_content = ::fcntl(reusable->content_fd(), F_DUPFD_CLOEXEC, 0);
    REQUIRE(live_content >= 0);
    auto busy_cleanup = reusable->cleanup();
    REQUIRE(!busy_cleanup.has_value());
    REQUIRE(busy_cleanup.error().find("unmount materialization") != std::string::npos);
    ::close(live_content);
    REQUIRE(reusable->cleanup().has_value());

    const auto single_file = tree.root() / "single.txt";
    {
        std::ofstream single{single_file};
        single << "single";
    }
    auto file_registry = glove::supervisor::path_alias_registry::build(
        {policy_for("single", single_file, "/workspace/single.txt", quota_bytes)}
    );
    REQUIRE(file_registry.has_value());
    auto file_grant = file_registry->resolve({
        .alias = "single",
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 300,
        .max_bytes = quota_bytes,
    });
    REQUIRE(file_grant.has_value());
    auto file_materialized =
        glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
            materialization_root.string(), "session-file", *file_grant
        );
    REQUIRE(file_materialized.has_value());
    REQUIRE(!file_materialized->is_directory());
    std::array<char, 16> file_buffer{};
    REQUIRE(::read(file_materialized->content_fd(), file_buffer.data(), file_buffer.size()) == 6);
    const std::string_view copied_file{file_buffer.data(), 6};
    REQUIRE(copied_file == "single");
    REQUIRE(file_materialized->cleanup().has_value());

    const auto large_file = source / "large.bin";
    {
        std::ofstream large{large_file, std::ios::binary};
        std::string data(static_cast<std::size_t>(page_bytes * 2U), '\0');
        large.write(data.data(), static_cast<std::streamsize>(data.size()));
    }
    auto small_grant = registry->resolve({
        .alias = "workspace",
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 300,
        .max_bytes = page_bytes,
    });
    REQUIRE(small_grant.has_value());
    auto oversized = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-small", *small_grant
    );
    REQUIRE(!oversized.has_value());
    REQUIRE(oversized.error().find("quota exceeded") != std::string::npos);
    REQUIRE(count_entries(materialization_root) == 0);
    REQUIRE(std::filesystem::remove(large_file));

    const auto symlink = source / "escape";
    REQUIRE(::symlink("/etc", symlink.c_str()) == 0);
    auto unsafe = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-symlink", *grant
    );
    REQUIRE(!unsafe.has_value());
    REQUIRE(unsafe.error().find("symlink or special file") != std::string::npos);
    REQUIRE(count_entries(materialization_root) == 0);
    REQUIRE(std::filesystem::remove(symlink));

    const auto external_file = tree.root() / "outside.txt";
    {
        std::ofstream external{external_file};
        external << "outside";
    }
    const auto hardlink = source / "hardlink";
    REQUIRE(::link(external_file.c_str(), hardlink.c_str()) == 0);
    auto hardlinked = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-hardlink", *grant
    );
    REQUIRE(!hardlinked.has_value());
    REQUIRE(hardlinked.error().find("hardlinked file") != std::string::npos);
    REQUIRE(count_entries(materialization_root) == 0);
    REQUIRE(std::filesystem::remove(hardlink));
    REQUIRE(std::filesystem::remove(external_file));

    const auto insecure_root = tree.root() / "insecure-materializations";
    REQUIRE(std::filesystem::create_directory(insecure_root));
    REQUIRE(::chmod(insecure_root.c_str(), 0755) == 0);
    auto insecure = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        insecure_root.string(), "session-insecure", *grant
    );
    REQUIRE(!insecure.has_value());
    REQUIRE(insecure.error().find("owner-only") != std::string::npos);

    const auto moved_source = tree.root() / "source-original";
    std::filesystem::rename(source, moved_source);
    REQUIRE(std::filesystem::create_directory(source));
    auto replaced = glove::supervisor::linux_detail::ephemeral_copy_materialization::create(
        materialization_root.string(), "session-replaced", *grant
    );
    REQUIRE(!replaced.has_value());
    REQUIRE(replaced.error().find("identity changed") != std::string::npos);
    REQUIRE(count_entries(materialization_root) == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
