#pragma once

// Bidirectional in-memory transport pair. Test helper that lets one half
// (the "agent") drive the other half (the "kernel") without spawning a
// process or opening real fds. Each direction has its own queue + cv;
// send() pushes to the peer's recv queue.

#include "glove/mcp/transport.hpp"

#include <condition_variable>
#include <expected>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <utility>

namespace glove::testing {

namespace detail {

struct channel {
    std::mutex mu;
    std::condition_variable cv;
    std::queue<std::string> messages;
    bool closed = false;
};

class mock_transport final : public glove::mcp::transport {
public:
    mock_transport(std::shared_ptr<channel> recv_ch, std::shared_ptr<channel> send_ch)
        : recv_ch_{std::move(recv_ch)}, send_ch_{std::move(send_ch)} {}

    auto send(std::string_view frame) -> std::expected<void, std::string> override {
        {
            std::scoped_lock lock{send_ch_->mu};
            if (send_ch_->closed) {
                return std::unexpected(std::string{"mock_pair: send to closed channel"});
            }
            send_ch_->messages.emplace(frame);
        }
        send_ch_->cv.notify_one();
        return {};
    }

    auto recv() -> std::expected<std::string, std::string> override {
        std::unique_lock lock{recv_ch_->mu};
        recv_ch_->cv.wait(lock, [&] { return !recv_ch_->messages.empty() || recv_ch_->closed; });
        if (recv_ch_->messages.empty()) {
            return std::unexpected(std::string{"mock_pair: recv from closed channel"});
        }
        std::string out = std::move(recv_ch_->messages.front());
        recv_ch_->messages.pop();
        return out;
    }

private:
    std::shared_ptr<channel> recv_ch_;
    std::shared_ptr<channel> send_ch_;
};

} // namespace detail

class mock_pair {
public:
    mock_pair()
        : a_to_k_{std::make_shared<detail::channel>()},
          k_to_a_{std::make_shared<detail::channel>()},
          agent_{std::make_unique<detail::mock_transport>(k_to_a_, a_to_k_)},
          kernel_{std::make_unique<detail::mock_transport>(a_to_k_, k_to_a_)} {}

    auto agent_side() -> glove::mcp::transport& { return *agent_; }

    auto kernel_side() -> glove::mcp::transport& { return *kernel_; }

    // Closes the agent→kernel direction so the kernel's recv() returns an
    // error after pending frames are drained, letting `server.run()` exit
    // cleanly at the end of a test.
    void close_agent_to_kernel() {
        {
            std::scoped_lock lock{a_to_k_->mu};
            a_to_k_->closed = true;
        }
        a_to_k_->cv.notify_all();
    }

private:
    std::shared_ptr<detail::channel> a_to_k_;
    std::shared_ptr<detail::channel> k_to_a_;
    std::unique_ptr<detail::mock_transport> agent_;
    std::unique_ptr<detail::mock_transport> kernel_;
};

} // namespace glove::testing
