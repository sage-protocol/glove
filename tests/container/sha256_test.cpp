#include "sha256.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <span>
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

auto bytes(std::string_view value) -> std::span<const unsigned char> {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

auto run() -> int {
    const auto empty = glove::container::detail::sha256_hex({});
    REQUIRE(empty.has_value());
    REQUIRE(
        *empty == "e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855"
    );

    const auto abc = glove::container::detail::sha256_hex(bytes("abc"));
    REQUIRE(abc.has_value());
    REQUIRE(
        *abc == "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad"
    );

    std::array<unsigned char, 1'000'000> million_a{};
    million_a.fill(static_cast<unsigned char>('a'));
    const auto large = glove::container::detail::sha256_hex(million_a);
    REQUIRE(large.has_value());
    REQUIRE(
        *large == "cdc76e5c9914fb9281a1c7e284d73e67"
                  "f1809a48a497200e046d39ccc7112cd0"
    );

    std::string pattern = "/tmp/glove-sha256-test-XXXXXX";
    const int descriptor = ::mkstemp(pattern.data());
    REQUIRE(descriptor >= 0);
    REQUIRE(::write(descriptor, "abc", 3) == 3);
    const auto file = glove::container::detail::sha256_fd_hex(descriptor, 3);
    REQUIRE(file == abc);
    REQUIRE(!glove::container::detail::sha256_fd_hex(descriptor, 2).has_value());
    REQUIRE(::close(descriptor) == 0);
    REQUIRE(::unlink(pattern.c_str()) == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
