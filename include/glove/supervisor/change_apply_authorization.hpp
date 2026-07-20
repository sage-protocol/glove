#pragma once

#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace glove::supervisor {

inline constexpr std::uint8_t change_apply_authorization_schema_version = 1;
inline constexpr std::uint64_t maximum_change_apply_authorization_lifetime_ms =
    std::uint64_t{5} * 60U * 1'000U;

// Exact local consequences approved by the administrator-owned presence helper.
// The helper signs the canonical JSON returned by
// change_apply_authorization_signing_payload. Its private key is never part of
// Glove or Sage configuration.
struct change_apply_authorization_claims {
    std::uint8_t schema_version = change_apply_authorization_schema_version;
    std::string audience = "gloved";
    std::string key_id;
    std::string grant_id;
    std::string executor_node_id;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string manifest_digest;
    std::uint64_t policy_revision = 0;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;

    auto operator==(const change_apply_authorization_claims&) const -> bool = default;
};

struct change_apply_authorization {
    change_apply_authorization_claims claims;
    std::string signature;
    std::string authorization_digest;
    std::string canonical_json;

    auto operator==(const change_apply_authorization&) const -> bool = default;
};

// Expected values come from Glove-owned state: the accepted plan, retained
// stage, exposure registry, and current policy. No field is supplied by the
// remote controller at verification time.
struct change_apply_authorization_context {
    std::string executor_node_id;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string manifest_digest;
    std::uint64_t policy_revision = 0;
};

// Implementations own their root-controlled key policy and cryptographic
// backend. Test doubles may implement this interface, but Glove must not
// advertise apply capability until a production verifier is configured.
class change_apply_signature_verifier {
public:
    change_apply_signature_verifier() = default;
    change_apply_signature_verifier(const change_apply_signature_verifier&) = delete;
    auto operator=(const change_apply_signature_verifier&)
        -> change_apply_signature_verifier& = delete;
    change_apply_signature_verifier(change_apply_signature_verifier&&) = delete;
    auto operator=(change_apply_signature_verifier&&) -> change_apply_signature_verifier& = delete;
    virtual ~change_apply_signature_verifier() = default;

    [[nodiscard]] virtual auto verify(
        const change_apply_authorization_claims& claims,
        std::span<const unsigned char> canonical_claims,
        std::string_view signature,
        std::uint64_t now_ms
    ) const -> result<void> = 0;
};

[[nodiscard]] auto
change_apply_authorization_signing_payload(const change_apply_authorization_claims& claims)
    -> result<std::string>;

// Assemble the canonical transport envelope after an external helper signs the
// payload. This function does not authenticate the signature.
[[nodiscard]] auto encode_change_apply_authorization(
    const change_apply_authorization_claims& claims, std::string signature
) -> result<change_apply_authorization>;

// Strictly decode, re-encode, bind to Glove-owned context, enforce the time
// window, and finally invoke the root-controlled signature verifier.
[[nodiscard]] auto verify_change_apply_authorization(
    std::string_view canonical_json,
    const change_apply_authorization_context& expected,
    std::uint64_t now_ms,
    const change_apply_signature_verifier& verifier
) -> result<change_apply_authorization>;

} // namespace glove::supervisor
