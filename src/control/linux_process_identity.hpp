#pragma once

#include "glove/control/session_registry.hpp"

#include <sys/types.h>

#include <expected>
#include <string>

namespace glove::control::linux_detail {

enum class linux_process_identity_observation : std::uint8_t {
    exact,
    absent,
    mismatch,
};

[[nodiscard]] auto capture_linux_process_identity(::pid_t pid)
    -> std::expected<::glove::control::linux_process_identity, std::string>;

[[nodiscard]] auto
observe_linux_process_identity(const ::glove::control::linux_process_identity& expected)
    -> std::expected<linux_process_identity_observation, std::string>;

} // namespace glove::control::linux_detail
