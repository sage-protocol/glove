#include "glove/supervisor/change_apply_trust_policy.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
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
        std::string pattern = "/tmp/glove-change-apply-trust-test-XXXXXX";
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

auto write_policy(const std::filesystem::path& path, std::string_view contents, int mode = 0600)
    -> bool {
    const int descriptor =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, static_cast<mode_t>(mode));
    if (descriptor < 0) {
        return false;
    }
    const auto written = ::write(descriptor, contents.data(), contents.size());
    const bool closed = ::close(descriptor) == 0;
    return written == static_cast<ssize_t>(contents.size()) && closed;
}

auto policy_json(std::string_view first_key = "admin-1", std::string_view second_key = "admin-2")
    -> std::string {
    return std::string{"{\"schema_version\":1,\"revision\":4,\"keys\":[{\"key_id\":\""} +
           std::string{first_key} + "\",\"algorithm\":\"ed25519\",\"public_key_base64url\":\"" +
           std::string(43, 'A') +
           "\",\"not_before_ms\":1000,\"not_after_ms\":10000},{\"key_id\":\"" +
           std::string{second_key} + "\",\"algorithm\":\"ed25519\",\"public_key_base64url\":\"" +
           std::string(42, 'B') + "A\",\"not_before_ms\":2000,\"not_after_ms\":20000}]}";
}

auto run() -> int {
    using glove::supervisor::change_apply_trust_policy;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto policy_path = temporary.root() / "trust.json";
    REQUIRE(write_policy(policy_path, policy_json()));
    auto policy = change_apply_trust_policy::load(policy_path);
    REQUIRE(policy.has_value());
    REQUIRE(policy->revision() == 4);
    REQUIRE(policy->keys().size() == 2U);
    REQUIRE(policy->active_key("admin-1", 5'000).has_value());
    REQUIRE(!policy->active_key("admin-1", 10'000).has_value());
    REQUIRE(!policy->active_key("missing", 5'000).has_value());
    REQUIRE(policy->authorization_key("admin-1", 1'000, 9'000, 5'000).has_value());
    REQUIRE(!policy->authorization_key("admin-1", 999, 9'000, 5'000).has_value());
    REQUIRE(!policy->authorization_key("admin-1", 1'000, 10'001, 5'000).has_value());

    const auto unordered_path = temporary.root() / "unordered.json";
    REQUIRE(write_policy(unordered_path, policy_json("admin-2", "admin-1")));
    REQUIRE(!change_apply_trust_policy::load(unordered_path).has_value());

    const auto weak_path = temporary.root() / "weak.json";
    REQUIRE(write_policy(weak_path, policy_json(), 0644));
    REQUIRE(!change_apply_trust_policy::load(weak_path).has_value());

    const auto link_path = temporary.root() / "link.json";
    REQUIRE(::symlink(policy_path.c_str(), link_path.c_str()) == 0);
    REQUIRE(!change_apply_trust_policy::load(link_path).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
