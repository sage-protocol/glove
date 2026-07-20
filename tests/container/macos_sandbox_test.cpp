// Stage 1 integration test (macOS): the spawner must contain an ARBITRARY,
// non-glove-aware binary via an SBPL profile applied through sandbox-exec —
// not rely on the agent self-sandboxing. We spawn /bin/sh with a probe that
// reports whether it can write inside the configured workspace (must) and
// outside it, in $HOME (must not), and read a benign file outside it (must
// not). Reaching any result at all also proves
// the system.sb import lets a dynamically linked binary start under the
// sandbox.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    const char* home = std::getenv("HOME");
    REQUIRE(home != nullptr && *home != '\0');

    // A writable workspace under $HOME, so the "allow workspace / deny the rest
    // of $HOME" distinction is meaningful (a /tmp workspace would be covered by
    // the default scratch-dir allowance and prove nothing).
    std::string ws = std::string{home} + "/.glove_ws_test_" + std::to_string(::getpid());
    std::error_code ec;
    std::filesystem::create_directories(ws, ec);
    REQUIRE(!ec);

    std::string evil = std::string{home} + "/.glove_evil_" + std::to_string(::getpid());

    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws, .writable = true});

    // Probe: report deny/allow for a write outside the workspace and inside it,
    // plus a read outside the workspace. The executable itself is an implicit
    // runtime grant; unrelated host files are not.
    std::string script = "if touch '" + evil + "' 2>/dev/null; then h=WRITE; else h=DENY; fi; ";
    script += "if touch '" + ws + "/ok' 2>/dev/null; then w=WRITE; else w=DENY; fi; ";
    script += "if head -c1 '" + std::string{__FILE__} +
              "' >/dev/null 2>&1; then r=READ; else r=DENY; fi; ";
    script += "echo \"home=$h ws=$w outside_read=$r\"";

    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or = spawner->spawn(prof, {"/bin/sh", "-c", script});
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);

    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    std::fprintf(stderr, "probe: %s\n", line->c_str());

    const bool home_denied = line->find("home=DENY") != std::string::npos;
    const bool ws_allowed = line->find("ws=WRITE") != std::string::npos;
    const bool outside_read_denied = line->find("outside_read=DENY") != std::string::npos;

    std::filesystem::remove_all(ws, ec);
    std::filesystem::remove(evil, ec);

    REQUIRE(home_denied);
    REQUIRE(ws_allowed);
    REQUIRE(outside_read_denied);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
