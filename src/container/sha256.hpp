#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace glove::container::detail {

// Dependency-free SHA-256 used for versioned launch-profile commitments. It is
// an integrity primitive only; receipt authenticity is supplied by the future
// supervisor audit signature.
[[nodiscard]] auto sha256_hex(std::span<const unsigned char> input)
    -> std::expected<std::string, std::string>;

// Hash a seek-independent regular-file view without changing its offset.
// `max_bytes` is a caller-owned denial-of-service bound.
[[nodiscard]] auto sha256_fd_hex(int descriptor, std::uint64_t max_bytes)
    -> std::expected<std::string, std::string>;

} // namespace glove::container::detail
