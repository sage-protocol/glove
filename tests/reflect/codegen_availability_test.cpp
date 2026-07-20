// Verifies that <glove/reflect/codegen.hpp> can be included in any build, and
// that `reflection_available` correctly reports whether the project was
// compiled against a P2996-capable toolchain. This is a build-time smoke test
// for the GLOVE_REFLECTION option — the actual reflection-driven codec lands
// when a P2996 compiler is wired in.

#include "glove/reflect/codegen.hpp"

auto main() -> int {
#if defined(GLOVE_HAS_REFLECTION)
    return 0; // reflection-aware build path; future tests live in a
              // separate binary that requires the option
#else
    static_assert(!glove::reflect::reflection_available);
    return 0;
#endif
}
