#include "sha256.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <system_error>

namespace glove::container::detail {

namespace {

constexpr std::array<std::uint32_t, 64> round_constants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
};

// SHA-256's fixed schedule is indexed only by the explicit loop bounds below.
// NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
class sha256_state {
public:
    void update(std::span<const unsigned char> input) noexcept {
        for (const unsigned char byte : input) {
            block_[block_size_++] = byte;
            if (block_size_ == block_.size()) {
                transform();
                block_size_ = 0;
            }
        }
        total_bytes_ += static_cast<std::uint64_t>(input.size());
    }

    [[nodiscard]] auto finish() noexcept -> std::array<unsigned char, 32> {
        block_[block_size_++] = 0x80U;
        if (block_size_ > 56U) {
            while (block_size_ < block_.size()) {
                block_[block_size_++] = 0;
            }
            transform();
            block_size_ = 0;
        }
        while (block_size_ < 56U) {
            block_[block_size_++] = 0;
        }
        const std::uint64_t bit_length = total_bytes_ * 8U;
        for (std::size_t index = 0; index < 8U; ++index) {
            const auto shift = static_cast<unsigned int>((7U - index) * 8U);
            block_[56U + index] = static_cast<unsigned char>(bit_length >> shift);
        }
        transform();

        std::array<unsigned char, 32> digest{};
        for (std::size_t word = 0; word < state_.size(); ++word) {
            for (std::size_t byte = 0; byte < 4U; ++byte) {
                const auto shift = static_cast<unsigned int>((3U - byte) * 8U);
                digest[word * 4U + byte] = static_cast<unsigned char>(state_[word] >> shift);
            }
        }
        return digest;
    }

private:
    void transform() noexcept {
        std::array<std::uint32_t, 64> schedule{};
        for (std::size_t index = 0; index < 16U; ++index) {
            const std::size_t offset = index * 4U;
            schedule[index] = static_cast<std::uint32_t>(block_[offset]) << 24U |
                              static_cast<std::uint32_t>(block_[offset + 1U]) << 16U |
                              static_cast<std::uint32_t>(block_[offset + 2U]) << 8U |
                              static_cast<std::uint32_t>(block_[offset + 3U]);
        }
        for (std::size_t index = 16U; index < schedule.size(); ++index) {
            const std::uint32_t first = std::rotr(schedule[index - 15U], 7) ^
                                        std::rotr(schedule[index - 15U], 18) ^
                                        (schedule[index - 15U] >> 3U);
            const std::uint32_t second = std::rotr(schedule[index - 2U], 17) ^
                                         std::rotr(schedule[index - 2U], 19) ^
                                         (schedule[index - 2U] >> 10U);
            schedule[index] = schedule[index - 16U] + first + schedule[index - 7U] + second;
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];
        for (std::size_t index = 0; index < schedule.size(); ++index) {
            const std::uint32_t choose = (e & f) ^ (~e & g);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t upper_a = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            const std::uint32_t upper_e = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            const std::uint32_t first =
                h + upper_e + choose + round_constants[index] + schedule[index];
            const std::uint32_t second = upper_a + majority;
            h = g;
            g = f;
            f = e;
            e = d + first;
            d = c;
            c = b;
            b = a;
            a = first + second;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_ = {
        0x6a09e667U,
        0xbb67ae85U,
        0x3c6ef372U,
        0xa54ff53aU,
        0x510e527fU,
        0x9b05688cU,
        0x1f83d9abU,
        0x5be0cd19U,
    };
    std::array<unsigned char, 64> block_{};
    std::size_t block_size_ = 0;
    std::uint64_t total_bytes_ = 0;
};

auto encode_digest(const std::array<unsigned char, 32>& digest) -> std::string {
    constexpr std::array digits = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    std::string encoded;
    encoded.reserve(digest.size() * 2U);
    for (const unsigned char byte : digest) {
        encoded.push_back(digits[byte >> 4U]);
        encoded.push_back(digits[byte & 0x0fU]);
    }
    return encoded;
}

// NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)

} // namespace

auto sha256_hex(std::span<const unsigned char> input) -> std::expected<std::string, std::string> {
    if (input.size() > std::numeric_limits<std::uint64_t>::max() / 8U) {
        return std::unexpected(std::string{"SHA-256 input exceeds its length encoding"});
    }
    sha256_state state;
    state.update(input);
    return encode_digest(state.finish());
}

auto sha256_fd_hex(int descriptor, std::uint64_t max_bytes)
    -> std::expected<std::string, std::string> {
    if (descriptor < 0 || max_bytes == 0 ||
        max_bytes > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        return std::unexpected(std::string{"invalid SHA-256 file input"});
    }
    std::array<unsigned char, std::size_t{64} * 1024U> buffer{};
    std::uint64_t offset = 0;
    sha256_state state;
    while (true) {
        const std::uint64_t remaining = max_bytes - offset;
        if (remaining == 0) {
            unsigned char extra = 0;
            const ::ssize_t beyond = ::pread(descriptor, &extra, 1, static_cast<off_t>(offset));
            if (beyond < 0 && errno == EINTR) {
                continue;
            }
            if (beyond < 0) {
                return std::unexpected(
                    std::string{"read SHA-256 file input: "} +
                    std::error_code{errno, std::generic_category()}.message()
                );
            }
            if (beyond != 0) {
                return std::unexpected(std::string{"SHA-256 file input exceeds its bound"});
            }
            break;
        }
        const auto requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size()))
        );
        const ::ssize_t read =
            ::pread(descriptor, buffer.data(), requested, static_cast<off_t>(offset));
        if (read < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                std::string{"read SHA-256 file input: "} +
                std::error_code{errno, std::generic_category()}.message()
            );
        }
        if (read == 0) {
            break;
        }
        const auto count = static_cast<std::size_t>(read);
        state.update(std::span<const unsigned char>{buffer.data(), count});
        offset += static_cast<std::uint64_t>(count);
    }
    return encode_digest(state.finish());
}

} // namespace glove::container::detail
