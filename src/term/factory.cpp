#include "glove/term/terminal.hpp"

#include <memory>

namespace glove::term {

auto make_null_terminal() -> std::unique_ptr<terminal>;

#if defined(GLOVE_WITH_GHOSTTY)
auto make_ghostty_terminal() -> std::unique_ptr<terminal>;
#endif

auto make_default_terminal() -> std::unique_ptr<terminal> {
#if defined(GLOVE_WITH_GHOSTTY)
    if (auto t = make_ghostty_terminal()) {
        return t;
    }
#endif
    return make_null_terminal();
}

} // namespace glove::term
