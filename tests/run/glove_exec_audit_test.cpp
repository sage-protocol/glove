// Direct-agent mode must leave a durable launch/exit trail even though it does
// not use the MCP kernel.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#ifndef GLOVE_BIN
#    error "GLOVE_BIN must point at the glove executable"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    std::error_code ec;
    auto base =
        std::filesystem::temp_directory_path() / ("glove_exec_audit_" + std::to_string(::getpid()));
    auto workspace = base / "workspace";
    auto audit = base / "audit.jsonl";
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);

    const ::pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        ::execl(
            GLOVE_BIN,
            GLOVE_BIN,
            "exec",
            "--workspace",
            workspace.c_str(),
            "--audit-log",
            audit.c_str(),
            "--",
            "/usr/bin/true",
            static_cast<char*>(nullptr)
        );
        std::_Exit(127);
    }
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);

    std::ifstream stream{audit};
    REQUIRE(stream.good());
    const std::string contents(
        std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}
    );
    REQUIRE(contents.find("\"action\":\"agent_launch\"") != std::string::npos);
    REQUIRE(contents.find("\"action\":\"agent_exit\"") != std::string::npos);

    std::filesystem::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
