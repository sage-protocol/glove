#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace glove::container {

// Portable SHA-256 used for cross-boundary content commitments. This function
// accepts bytes already bounded by the caller and returns lowercase hex.
[[nodiscard]] auto sha256_hex(std::span<const unsigned char> input)
    -> std::expected<std::string, std::string>;

// Hash a seek-independent regular-file view without changing its offset.
// `max_bytes` is a caller-owned denial-of-service bound.
[[nodiscard]] auto sha256_fd_hex(int descriptor, std::uint64_t max_bytes)
    -> std::expected<std::string, std::string>;

} // namespace glove::container
