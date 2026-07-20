#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"

#include <expected>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace glove::audit {

namespace {

class memory_sink_impl final : public memory_sink {
public:
    auto record(const event& e) -> std::expected<void, std::string> override {
        std::scoped_lock lock{mu_};
        events_.push_back(e);
        return {};
    }

    auto take_locked() -> std::vector<event> {
        std::scoped_lock lock{mu_};
        std::vector<event> out;
        out.swap(events_);
        return out;
    }

private:
    std::mutex mu_;
    std::vector<event> events_;
};

} // namespace

auto memory_sink::take() -> std::vector<event> {
    return static_cast<memory_sink_impl*>(this)->take_locked();
}

auto make_memory_sink() -> std::shared_ptr<memory_sink> {
    return std::make_shared<memory_sink_impl>();
}

} // namespace glove::audit
