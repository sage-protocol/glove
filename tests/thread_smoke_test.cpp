// Thread smoke test: drives the terminal from multiple threads through its
// internal mutex. TSan should be silent; if a future change introduces a race
// here it will fail this test.

#include "glove/term/terminal.hpp"

#include <atomic>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr int thread_count = 4;
constexpr int writes_per_thread = 64;

} // namespace

auto main() -> int {
    auto term = glove::term::make_default_terminal();
    if (!term) {
        std::fprintf(stderr, "terminal factory returned null\n");
        return 1;
    }

    std::atomic<int> writes{0};
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (int t = 0; t < thread_count; ++t) {
        workers.emplace_back([&, t] {
            for (int i = 0; i < writes_per_thread; ++i) {
                std::string line = "t";
                line.append(std::to_string(t));
                line.push_back(':');
                line.append(std::to_string(i));
                line.push_back('\n');
                term->write(line);
                writes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    term->flush();

    const int expected = thread_count * writes_per_thread;
    if (writes.load() != expected) {
        std::fprintf(stderr, "expected %d writes, got %d\n", expected, writes.load());
        return 1;
    }
    return 0;
}
