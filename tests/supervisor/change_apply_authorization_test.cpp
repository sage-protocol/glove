#include "glove/supervisor/change_apply_authorization.hpp"

#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class exact_verifier final : public glove::supervisor::change_apply_signature_verifier {
public:
    exact_verifier(std::string payload, bool accept)
        : payload_{std::move(payload)}, accept_{accept} {}

    auto verify(
        const glove::supervisor::change_apply_authorization_claims& claims,
        std::span<const unsigned char> canonical_claims,
        std::string_view signature,
        std::uint64_t now_ms
    ) const -> glove::supervisor::result<void> override {
        const std::string_view payload{
            reinterpret_cast<const char*>(canonical_claims.data()), canonical_claims.size()
        };
        if (!accept_ || claims.key_id != "admin-key-1" || signature != signature_value ||
            payload != payload_ || now_ms != 2'000) {
            return std::unexpected(std::string{"signature mismatch"});
        }
        return {};
    }

    static constexpr std::string_view signature_value = "dGVzdC1vbmx5LXNpZ25hdHVyZS12YWx1ZQ==";

private:
    std::string payload_;
    bool accept_ = false;
};

auto claims() -> glove::supervisor::change_apply_authorization_claims {
    return {
        .schema_version = 1,
        .audience = "gloved",
        .key_id = "admin-key-1",
        .grant_id = "grant-1",
        .executor_node_id = "node-1",
        .session_id = "session-1",
        .controller_plan_digest = std::string(64, 'a'),
        .plan_content_digest = std::string(64, 'b'),
        .exposure_id = "workspace",
        .generation = 7,
        .scope_digest = std::string(64, 'c'),
        .manifest_digest = std::string(64, 'd'),
        .policy_revision = 9,
        .issued_at_ms = 1'000,
        .expires_at_ms = 61'000,
    };
}

auto context(const glove::supervisor::change_apply_authorization_claims& value)
    -> glove::supervisor::change_apply_authorization_context {
    return {
        .executor_node_id = value.executor_node_id,
        .session_id = value.session_id,
        .controller_plan_digest = value.controller_plan_digest,
        .plan_content_digest = value.plan_content_digest,
        .exposure_id = value.exposure_id,
        .generation = value.generation,
        .scope_digest = value.scope_digest,
        .manifest_digest = value.manifest_digest,
        .policy_revision = value.policy_revision,
    };
}

auto run() -> int {
    using namespace glove::supervisor;

    const auto value = claims();
    auto payload = change_apply_authorization_signing_payload(value);
    REQUIRE(payload.has_value());
    auto encoded =
        encode_change_apply_authorization(value, std::string{exact_verifier::signature_value});
    REQUIRE(encoded.has_value());
    REQUIRE(encoded->authorization_digest.size() == 64U);
    REQUIRE(encoded->canonical_json.find("host_path") == std::string::npos);
    auto repeated =
        encode_change_apply_authorization(value, std::string{exact_verifier::signature_value});
    REQUIRE(repeated.has_value());
    REQUIRE(repeated->canonical_json == encoded->canonical_json);

    exact_verifier verifier{*payload, true};
    auto verified =
        verify_change_apply_authorization(encoded->canonical_json, context(value), 2'000, verifier);
    REQUIRE(verified.has_value());
    REQUIRE(verified->claims == value);
    REQUIRE(verified->authorization_digest == encoded->authorization_digest);

    auto wrong_context = context(value);
    wrong_context.generation += 1;
    REQUIRE(
        !verify_change_apply_authorization(encoded->canonical_json, wrong_context, 2'000, verifier)
             .has_value()
    );
    REQUIRE(!verify_change_apply_authorization(
                 encoded->canonical_json, context(value), value.expires_at_ms, verifier
    )
                 .has_value());
    exact_verifier rejecting{*payload, false};
    REQUIRE(!verify_change_apply_authorization(
                 encoded->canonical_json, context(value), 2'000, rejecting
    )
                 .has_value());

    auto tampered = encoded->canonical_json;
    const auto digest_position = tampered.find(std::string(64, 'd'));
    REQUIRE(digest_position != std::string::npos);
    tampered[digest_position] = 'e';
    REQUIRE(
        !verify_change_apply_authorization(tampered, context(value), 2'000, verifier).has_value()
    );

    auto long_lived = value;
    long_lived.expires_at_ms =
        long_lived.issued_at_ms + maximum_change_apply_authorization_lifetime_ms + 1U;
    REQUIRE(!change_apply_authorization_signing_payload(long_lived).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
