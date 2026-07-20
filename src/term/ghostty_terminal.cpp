// libghostty-backed terminal. Compiled only when GLOVE_WITH_GHOSTTY is set.
//
// Boundary contract: the implementation here owns one libghostty surface and
// forwards bytes to it. The libghostty C API is consumed via
// <ghostty/vt.h>; replace the TODO calls below with the real entry points
// once the library is vendored under third_party/ghostty/.

#include "glove/term/terminal.hpp"

#include <memory>
#include <mutex>
#include <string_view>

// IWYU pragma: keep
// #include <ghostty/vt.h>  // re-enable once the header is on the include path

namespace glove::term {

namespace {

class ghostty_terminal final : public terminal {
public:
    ghostty_terminal() = default;
    ~ghostty_terminal() override = default;
    ghostty_terminal(const ghostty_terminal&) = delete;
    ghostty_terminal& operator=(const ghostty_terminal&) = delete;
    ghostty_terminal(ghostty_terminal&&) = delete;
    ghostty_terminal& operator=(ghostty_terminal&&) = delete;

    void write(std::string_view text) override {
        std::scoped_lock lock(mu_);
        // TODO(glove): ghostty_vt_write(surface_, text.data(), text.size());
        (void)text;
    }

    void flush() override {
        std::scoped_lock lock(mu_);
        // TODO(glove): ghostty_vt_flush(surface_);
    }

private:
    std::mutex mu_;
    // ghostty_vt* surface_ = nullptr;
};

} // namespace

auto make_ghostty_terminal() -> std::unique_ptr<terminal> {
    return std::make_unique<ghostty_terminal>();
}

} // namespace glove::term
