#pragma once

#include <sys/types.h>

#include <expected>
#include <string>

namespace glove::control::detail {

// Private test seam for the mandatory same-owner peer-credential check. The
// production listener always supplies its effective uid; callers cannot
// configure or bypass that authority boundary.
[[nodiscard]] auto verify_peer_owner(int descriptor, ::uid_t expected_owner)
    -> std::expected<void, std::string>;

} // namespace glove::control::detail
