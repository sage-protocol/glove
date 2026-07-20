#include "glove/container/digest.hpp"

#include "sha256.hpp"

namespace glove::container {

auto sha256_hex(std::span<const unsigned char> input) -> std::expected<std::string, std::string> {
    return detail::sha256_hex(input);
}

auto sha256_fd_hex(int descriptor, std::uint64_t max_bytes)
    -> std::expected<std::string, std::string> {
    return detail::sha256_fd_hex(descriptor, max_bytes);
}

} // namespace glove::container
