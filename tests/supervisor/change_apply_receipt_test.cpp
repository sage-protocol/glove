#include "glove/supervisor/change_apply_receipt.hpp"

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

auto run() -> int {
    using namespace glove::supervisor;

    const change_apply_reservation_record reservation{
        .grant_id = "grant-1",
        .authorization_digest = std::string(64, 'a'),
        .manifest_digest = std::string(64, 'b'),
        .session_id = "session-1",
        .exposure_id = "workspace",
        .generation = 7,
        .scope_digest = std::string(64, 'c'),
        .source_identity_digest = std::string(64, 'd'),
        .baseline_tree_digest = std::string(64, 'e'),
        .staged_tree_digest = std::string(64, 'f'),
        .reserved_at_ms = 1'000,
    };
    const change_apply_exchange_result exchange{
        .candidate_name = ".glove-apply-v1-" + reservation.authorization_digest,
        .final_source_identity_digest = std::string(64, '0'),
        .final_tree_digest = reservation.staged_tree_digest,
    };
    auto receipt = build_change_apply_receipt(reservation, exchange, 2'000);
    REQUIRE(receipt.has_value());
    REQUIRE(receipt->state == "applied");
    REQUIRE(receipt->failure_code.empty());
    REQUIRE(receipt->authorization_digest == reservation.authorization_digest);
    REQUIRE(receipt->manifest_digest == reservation.manifest_digest);
    REQUIRE(receipt->receipt_digest.size() == 64U);
    REQUIRE(receipt->canonical_json.find("candidate_name") == std::string::npos);
    auto decoded = decode_change_apply_receipt(receipt->canonical_json);
    REQUIRE(decoded.has_value());
    REQUIRE(*decoded == *receipt);
    auto repeated = build_change_apply_receipt(reservation, exchange, 2'000);
    REQUIRE(repeated.has_value());
    REQUIRE(repeated->canonical_json == receipt->canonical_json);
    const change_apply_terminal_record applied_terminal{
        .grant_id = reservation.grant_id,
        .authorization_digest = reservation.authorization_digest,
        .manifest_digest = reservation.manifest_digest,
        .state = change_apply_terminal_state::applied,
        .receipt_digest = receipt->receipt_digest,
        .final_source_identity_digest = receipt->final_source_identity_digest,
        .failure_code = {},
        .completed_at_ms = receipt->completed_at_ms,
    };
    auto reconstructed = reconstruct_change_apply_receipt(reservation, applied_terminal);
    REQUIRE(reconstructed.has_value());
    REQUIRE(*reconstructed == *receipt);

    auto tampered = receipt->canonical_json;
    const auto position = tampered.find(reservation.manifest_digest);
    REQUIRE(position != std::string::npos);
    tampered[position] = 'c';
    REQUIRE(!decode_change_apply_receipt(tampered).has_value());

    auto wrong_exchange = exchange;
    wrong_exchange.final_tree_digest = reservation.baseline_tree_digest;
    REQUIRE(!build_change_apply_receipt(reservation, wrong_exchange, 2'000).has_value());
    REQUIRE(!build_change_apply_receipt(reservation, exchange, 999).has_value());

    auto failed = build_failed_change_apply_receipt(
        reservation, reservation.source_identity_digest, "interrupted_before_mutation", 2'000
    );
    REQUIRE(failed.has_value());
    REQUIRE(failed->state == "failed");
    REQUIRE(failed->failure_code == "interrupted_before_mutation");
    REQUIRE(!failed->canonical_json.empty());
    auto decoded_failed = decode_change_apply_receipt(failed->canonical_json);
    REQUIRE(decoded_failed.has_value());
    REQUIRE(*decoded_failed == *failed);
    const change_apply_terminal_record failed_terminal{
        .grant_id = reservation.grant_id,
        .authorization_digest = reservation.authorization_digest,
        .manifest_digest = reservation.manifest_digest,
        .state = change_apply_terminal_state::failed,
        .receipt_digest = failed->receipt_digest,
        .final_source_identity_digest = failed->final_source_identity_digest,
        .failure_code = failed->failure_code,
        .completed_at_ms = failed->completed_at_ms,
    };
    auto reconstructed_failed = reconstruct_change_apply_receipt(reservation, failed_terminal);
    REQUIRE(reconstructed_failed.has_value());
    REQUIRE(*reconstructed_failed == *failed);
    REQUIRE(!build_failed_change_apply_receipt(
                 reservation, reservation.source_identity_digest, "bad failure code", 2'000
    )
                 .has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
