#pragma once

#include <cstdint>
#include <string>

namespace glove::policy {

enum class decision : std::uint8_t { allow, deny };

// Outcome of a policy check. `reason` is human-readable and surfaces in
// audit logs and the error path of denied calls.
struct outcome {
    decision verdict = decision::deny;
    std::string reason;
};

} // namespace glove::policy
