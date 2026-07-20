#pragma once

#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace glove::supervisor::linux_detail {

inline constexpr std::uint64_t minimum_persistent_quota_bytes = std::uint64_t{32} * 1024U * 1024U;

[[nodiscard]] auto create_persistent_quota_image(
    int root_fd,
    std::string_view directory_name,
    std::string_view mount_path,
    std::uint64_t quota_bytes
) -> result<std::string>;

[[nodiscard]] auto recover_persistent_quota_image(
    int root_fd, std::string_view image_name, std::string_view mount_path, std::uint64_t quota_bytes
) -> result<void>;

[[nodiscard]] auto
validate_persistent_quota_image(int root_fd, std::string_view image_name, std::uint64_t quota_bytes)
    -> result<void>;

[[nodiscard]] auto remove_persistent_quota_image(int root_fd, std::string_view image_name)
    -> result<void>;

[[nodiscard]] auto persistent_quota_image_size(int root_fd, std::string_view image_name)
    -> result<std::uint64_t>;

[[nodiscard]] auto persistent_quota_image_name(std::string_view directory_name) -> std::string;

} // namespace glove::supervisor::linux_detail
