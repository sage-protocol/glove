#pragma once

#include "glove/audit/event.hpp"

#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace glove::audit {

// Append-only event sink. Implementations must be safe for concurrent record()
// calls — multiple decorators may share one sink across agent threads.
class sink {
public:
    sink() = default;
    sink(const sink&) = delete;
    sink& operator=(const sink&) = delete;
    sink(sink&&) = delete;
    sink& operator=(sink&&) = delete;
    virtual ~sink() = default;

    virtual auto record(const event& e) -> std::expected<void, std::string> = 0;
};

// In-memory sink. Records are buffered and exposed via take(); useful for
// tests and short-lived inspection windows.
class memory_sink : public sink {
public:
    auto take() -> std::vector<event>;
};

auto make_memory_sink() -> std::shared_ptr<memory_sink>;

// JSON-lines sink. One event per line; failures during write are surfaced as
// `std::unexpected`. The file is opened append-binary; concurrent processes
// targeting the same file are not supported.
auto make_jsonl_sink(const std::filesystem::path& path)
    -> std::expected<std::shared_ptr<sink>, std::string>;

} // namespace glove::audit
