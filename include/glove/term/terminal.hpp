#pragma once

#include <memory>
#include <string_view>

namespace glove::term {

// Abstract terminal sink. Implementations: null (stdout), ghostty (libghostty).
class terminal {
public:
    terminal() = default;
    terminal(const terminal&) = delete;
    terminal& operator=(const terminal&) = delete;
    terminal(terminal&&) = delete;
    terminal& operator=(terminal&&) = delete;
    virtual ~terminal() = default;

    virtual void write(std::string_view text) = 0;
    virtual void flush() = 0;
};

// Returns the configured terminal. Falls back to a stdout sink when no
// frontend is compiled in. Never null.
auto make_default_terminal() -> std::unique_ptr<terminal>;

} // namespace glove::term
