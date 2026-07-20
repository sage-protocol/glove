#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <string_view>

namespace {

[[noreturn]] void cpu_pressure() {
    volatile unsigned int counter = 0;
    for (;;) {
        counter = counter + 1U;
    }
}

[[noreturn]] void memory_pressure(std::size_t bytes) {
    void* memory =
        ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        std::_Exit(30);
    }
    auto* data = static_cast<volatile unsigned char*>(memory);
    for (std::size_t offset = 0; offset < bytes; offset += 4096) {
        data[offset] = 1;
    }
    std::_Exit(31);
}

[[noreturn]] void pid_pressure() {
    const ::pid_t helper = ::fork();
    if (helper == 0) {
        ::pause();
        std::_Exit(0);
    }
    if (helper < 0) {
        std::_Exit(20);
    }
    errno = 0;
    const ::pid_t denied = ::fork();
    const bool bounded = denied < 0 && errno == EAGAIN;
    if (denied == 0) {
        std::_Exit(21);
    }
    if (denied > 0) {
        (void)::kill(denied, SIGKILL);
        (void)::waitpid(denied, nullptr, 0);
    }
    (void)::kill(helper, SIGKILL);
    (void)::waitpid(helper, nullptr, 0);
    std::_Exit(bounded ? 0 : 22);
}

[[noreturn]] void sleep_until_signal() {
    for (;;) {
        ::pause();
    }
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        return 2;
    }
    const std::string_view mode{argv[1]};
    if (mode == "cpu") {
        cpu_pressure();
    }
    if (mode == "memory") {
        if (argc != 3) {
            return 2;
        }
        char* end = nullptr;
        const auto bytes = std::strtoull(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0' || bytes == 0) {
            return 2;
        }
        memory_pressure(static_cast<std::size_t>(bytes));
    }
    if (mode == "pids") {
        pid_pressure();
    }
    if (mode == "sleep") {
        sleep_until_signal();
    }
    if (mode == "exit" && argc == 3) {
        char* end = nullptr;
        const long code = std::strtol(argv[2], &end, 10);
        if (end != argv[2] && *end == '\0' && code >= 0 && code <= 255) {
            return static_cast<int>(code);
        }
    }
    return 2;
}
