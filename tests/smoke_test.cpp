// Smoke test: build a terminal, push bytes through it, exercise the heap so
// ASan has something to inspect. Failure modes report via non-zero exit.

#include "glove/term/terminal.hpp"
#include "glove/version.hpp"

#include <cstdio>
#include <memory>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    REQUIRE(!glove::version.empty());

    auto term = glove::term::make_default_terminal();
    REQUIRE(term);

    // Heap-backed string so ASan's redzone is in play.
    auto buf = std::make_unique<std::string>("smoke: ");
    buf->append(glove::version);
    buf->push_back('\n');
    term->write(std::string_view{*buf});
    term->flush();

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
