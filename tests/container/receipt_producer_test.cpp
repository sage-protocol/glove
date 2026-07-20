#include "glove/container/receipt_producer.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view controller_plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view profile_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-receipt-producer-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_key(const std::filesystem::path& path, std::string_view value, mode_t mode = 0600)
    -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << value << '\n';
    output.flush();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto append_byte(const std::filesystem::path& path) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::app};
    output.put('x');
    output.flush();
    return output.good();
}

auto receipt(std::uint64_t cpu_time_ms = 500) -> glove::container::resource_enforcement_receipt {
    return {
        .schema_version = 1,
        .profile_digest = std::string{profile_digest},
        .backend = glove::container::sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 60'000,
                .memory_bytes = std::uint64_t{512} * 1024U * 1024U,
                .pids = 128,
                .wall_time_ms = 120'000,
                .disk_bytes = std::uint64_t{1024} * 1024U * 1024U,
                .terminal_output_bytes = std::uint64_t{16} * 1024U * 1024U,
            },
        .mechanisms =
            {
                .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
                .memory = glove::container::enforcement_mechanism::cgroup_v2,
                .pids = glove::container::enforcement_mechanism::cgroup_v2,
                .wall_time = glove::container::enforcement_mechanism::watchdog,
                .disk = glove::container::enforcement_mechanism::filesystem_quota,
                .terminal_output = glove::container::enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = cpu_time_ms,
                .peak_memory_bytes = std::uint64_t{16} * 1024U * 1024U,
                .peak_pids = 2,
                .wall_time_ms = 750,
                .disk_bytes = 4096,
                .terminal_output_bytes = 1024,
            },
        .termination_cause = glove::container::resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = 1'000,
        .finished_at_ms = 1'750,
        .library_projections = {},
    };
}

auto bootstrap_reconciliation_and_durable_commit() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    REQUIRE(write_key(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = journal_path,
    };

    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    const auto genesis = (*producer)->anchor();
    REQUIRE(genesis.sequence == 0);
    REQUIRE(!(*producer)->bootstrap_reconciled());
    REQUIRE(!(*producer)->reserve_terminal().has_value());

    auto forged = genesis;
    forged.head_hmac[0] = '1';
    REQUIRE(!(*producer)->acknowledge_bootstrap(forged).has_value());
    REQUIRE(!(*producer)->bootstrap_reconciled());
    REQUIRE((*producer)->acknowledge_bootstrap(genesis).has_value());
    REQUIRE((*producer)->bootstrap_reconciled());
    REQUIRE(!glove::container::receipt_audit_producer::recover(config, genesis).has_value());

    auto reservation = (*producer)->reserve_terminal();
    REQUIRE(reservation.has_value());
    auto first = (*producer)->commit_terminal(
        std::move(*reservation), "session-1", controller_plan_digest, receipt()
    );
    REQUIRE(first.has_value());
    REQUIRE(first->sequence == 1);
    const auto first_anchor = (*producer)->anchor();
    auto page = (*producer)->page_after(genesis, 10);
    REQUIRE(page.has_value());
    REQUIRE(page->envelopes.size() == 1);
    REQUIRE(page->envelopes[0] == *first);
    producer->reset();

    auto recovered = glove::container::receipt_audit_producer::recover(config, genesis);
    REQUIRE(recovered.has_value());
    REQUIRE(!(*recovered)->bootstrap_reconciled());
    REQUIRE(!(*recovered)->reserve_terminal().has_value());
    auto pending = (*recovered)->page_after(genesis, 10);
    REQUIRE(pending.has_value());
    REQUIRE(pending->envelopes.size() == 1);
    REQUIRE((*recovered)->acknowledge_bootstrap(first_anchor).has_value());
    REQUIRE((*recovered)->bootstrap_reconciled());

    auto second_reservation = (*recovered)->reserve_terminal();
    REQUIRE(second_reservation.has_value());
    auto second =
        (*recovered)
            ->commit_terminal(
                std::move(*second_reservation), "session-2", controller_plan_digest, receipt(501)
            );
    REQUIRE(second.has_value());
    const auto second_anchor = (*recovered)->anchor();
    recovered->reset();

    auto caught_up = glove::container::receipt_audit_producer::recover(config, second_anchor);
    REQUIRE(caught_up.has_value());
    REQUIRE((*caught_up)->bootstrap_reconciled());
    auto caught_up_page = (*caught_up)->page_after(second_anchor, 10);
    REQUIRE(caught_up_page.has_value());
    REQUIRE(caught_up_page->envelopes.empty());
    caught_up->reset();

    auto ahead = second_anchor;
    ++ahead.sequence;
    REQUIRE(!glove::container::receipt_audit_producer::recover(config, ahead).has_value());
    auto divergent = second_anchor;
    divergent.head_hmac[0] = divergent.head_hmac[0] == 'a' ? 'b' : 'a';
    REQUIRE(!glove::container::receipt_audit_producer::recover(config, divergent).has_value());
    return 0;
}

auto concurrent_terminal_commits_are_serialized() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    REQUIRE(write_key(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = temp.root() / "receipts.journal",
    };
    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    std::atomic<std::uint64_t> committed = 0;
    {
        std::vector<std::thread> workers;
        workers.reserve(8);
        for (std::uint64_t index = 0; index < 8; ++index) {
            workers.emplace_back([&, index] {
                auto reservation = (*producer)->reserve_terminal();
                if (!reservation) {
                    return;
                }
                const auto session = "session-" + std::to_string(index);
                if ((*producer)->commit_terminal(
                        std::move(*reservation),
                        session,
                        controller_plan_digest,
                        receipt(500U + index)
                    )) {
                    committed.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        for (auto& worker : workers) {
            worker.join();
        }
    }
    REQUIRE(committed.load(std::memory_order_relaxed) == 8);
    REQUIRE((*producer)->anchor().sequence == 8);
    return 0;
}

auto capacity_is_reserved_before_a_session() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    REQUIRE(write_key(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = temp.root() / "receipts.journal",
        .max_journal_bytes = glove::container::max_receipt_journal_record_bytes,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    REQUIRE(!(*producer)->reserve_terminal().has_value());
    REQUIRE((*producer)->anchor().sequence == 0);
    return 0;
}

auto abandoned_capacity_reservation_is_released() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    REQUIRE(write_key(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = temp.root() / "receipts.journal",
        .max_journal_bytes = glove::container::max_receipt_journal_record_bytes + 128U,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    {
        auto reservation = (*producer)->reserve_terminal();
        REQUIRE(reservation.has_value());
        REQUIRE(!(*producer)->reserve_terminal().has_value());
    }
    REQUIRE((*producer)->reserve_terminal().has_value());
    return 0;
}

auto execution_bound_reservation_is_single_profile_authority() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    REQUIRE(write_key(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = temp.root() / "receipts.journal",
    };
    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    const auto genesis = (*producer)->anchor();
    REQUIRE((*producer)->acknowledge_bootstrap(genesis).has_value());

    auto reservation =
        (*producer)->reserve_terminal("session-bound", controller_plan_digest, profile_digest);
    REQUIRE(reservation.has_value());
    REQUIRE(
        reservation->matches_execution("session-bound", controller_plan_digest, profile_digest)
    );
    REQUIRE(
        !reservation->matches_execution("session-other", controller_plan_digest, profile_digest)
    );
    REQUIRE(!(*producer)
                 ->commit_terminal(
                     std::move(*reservation), "session-other", controller_plan_digest, receipt()
                 )
                 .has_value());
    REQUIRE((*producer)->anchor() == genesis);

    auto retry =
        (*producer)->reserve_terminal("session-bound", controller_plan_digest, profile_digest);
    REQUIRE(retry.has_value());
    auto committed = (*producer)->commit_terminal(
        std::move(*retry), "session-bound", controller_plan_digest, receipt()
    );
    REQUIRE(committed.has_value());
    REQUIRE(committed->session_id == "session-bound");
    REQUIRE(committed->receipt.profile_digest == profile_digest);
    auto confirmed = (*producer)->confirms_terminal(*committed);
    REQUIRE(confirmed.has_value());
    REQUIRE(*confirmed);
    auto lookup = (*producer)->terminal_for_execution(
        "session-bound", controller_plan_digest, profile_digest
    );
    REQUIRE(lookup.has_value());
    REQUIRE(lookup->has_value());
    REQUIRE(**lookup == *committed);
    auto missing = (*producer)->terminal_for_execution(
        "session-missing", controller_plan_digest, profile_digest
    );
    REQUIRE(missing.has_value());
    REQUIRE(!missing->has_value());
    auto tampered = *committed;
    tampered.receipt_digest = std::string(64, 'f');
    auto tampered_confirmation = (*producer)->confirms_terminal(tampered);
    REQUIRE(tampered_confirmation.has_value());
    REQUIRE(!*tampered_confirmation);

    const auto committed_anchor = (*producer)->anchor();
    producer->reset();
    auto recovered = glove::container::receipt_audit_producer::recover(config, committed_anchor);
    REQUIRE(recovered.has_value());
    auto recovered_confirmation = (*recovered)->confirms_terminal(*committed);
    REQUIRE(recovered_confirmation.has_value());
    REQUIRE(*recovered_confirmation);
    auto recovered_lookup =
        (*recovered)
            ->terminal_for_execution("session-bound", controller_plan_digest, profile_digest);
    REQUIRE(recovered_lookup.has_value());
    REQUIRE(recovered_lookup->has_value());
    REQUIRE(**recovered_lookup == *committed);
    return 0;
}

auto append_failure_never_acknowledges_terminal_success() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    REQUIRE(write_key(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = journal_path,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    const auto genesis = (*producer)->anchor();
    REQUIRE((*producer)->acknowledge_bootstrap(genesis).has_value());
    auto reservation = (*producer)->reserve_terminal();
    REQUIRE(reservation.has_value());
    REQUIRE(append_byte(journal_path));
    REQUIRE(!(*producer)
                 ->commit_terminal(
                     std::move(*reservation), "session-1", controller_plan_digest, receipt()
                 )
                 .has_value());
    REQUIRE((*producer)->anchor() == genesis);
    producer->reset();

    auto repaired = glove::container::receipt_audit_producer::recover(config, genesis);
    REQUIRE(repaired.has_value());
    REQUIRE((*repaired)->anchor() == genesis);
    return 0;
}

auto key_file_is_fail_closed() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    REQUIRE(write_key(key_path, audit_key, 0644));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = journal_path,
    };
    REQUIRE(!glove::container::receipt_audit_producer::initialize(config).has_value());
    REQUIRE(!std::filesystem::exists(journal_path));

    REQUIRE(::chmod(key_path.c_str(), 0600) == 0);
    const auto symlink_path = temp.root() / "audit-link.key";
    std::filesystem::create_symlink(key_path, symlink_path);
    auto symlink_config = config;
    symlink_config.key_path = symlink_path;
    REQUIRE(!glove::container::receipt_audit_producer::initialize(symlink_config).has_value());

    const auto hardlink_path = temp.root() / "audit-hardlink.key";
    std::filesystem::create_hard_link(key_path, hardlink_path);
    REQUIRE(!glove::container::receipt_audit_producer::initialize(config).has_value());
    auto hardlink_config = config;
    hardlink_config.key_path = hardlink_path;
    REQUIRE(!glove::container::receipt_audit_producer::initialize(hardlink_config).has_value());

    const auto short_key_path = temp.root() / "short.key";
    REQUIRE(write_key(short_key_path, "abcd"));
    auto short_config = config;
    short_config.key_path = short_key_path;
    REQUIRE(!glove::container::receipt_audit_producer::initialize(short_config).has_value());
    REQUIRE(!std::filesystem::exists(journal_path));
    return 0;
}

auto run() -> int {
    REQUIRE(bootstrap_reconciliation_and_durable_commit() == 0);
    REQUIRE(concurrent_terminal_commits_are_serialized() == 0);
    REQUIRE(capacity_is_reserved_before_a_session() == 0);
    REQUIRE(abandoned_capacity_reservation_is_released() == 0);
    REQUIRE(execution_bound_reservation_is_single_profile_authority() == 0);
    REQUIRE(append_failure_never_acknowledges_terminal_success() == 0);
    REQUIRE(key_file_is_fail_closed() == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
