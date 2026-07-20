#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"

#include "src/mcp/codec.hpp"
#include "src/mcp/jsonrpc.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::mcp {

namespace {

class jsonrpc_client final : public client {
public:
    explicit jsonrpc_client(std::unique_ptr<transport> t) : transport_{std::move(t)} {}

    auto initialize(std::string_view client_name, std::string_view client_version)
        -> std::expected<server_info, std::string> override {
        auto frame = codec::build_initialize_request(next_id(), client_name, client_version);
        if (!frame) {
            return std::unexpected(frame.error());
        }
        if (auto sent = transport_->send(*frame); !sent) {
            return std::unexpected(sent.error());
        }
        auto reply = transport_->recv();
        if (!reply) {
            return std::unexpected(reply.error());
        }
        auto env = codec::decode_response(*reply);
        if (!env) {
            return std::unexpected(env.error());
        }
        auto info = codec::parse_initialize_result(*env);
        if (!info) {
            return info;
        }

        // Per spec, follow up with the initialized notification. No response
        // is expected; the transport just writes the frame.
        auto note = codec::build_initialized_notification();
        if (!note) {
            return std::unexpected(note.error());
        }
        if (auto sent = transport_->send(*note); !sent) {
            return std::unexpected(sent.error());
        }
        return info;
    }

    auto list_tools() -> std::expected<std::vector<tool_descriptor>, std::string> override {
        auto frame = codec::build_tools_list_request(next_id());
        if (!frame) {
            return std::unexpected(frame.error());
        }
        auto sent = transport_->send(*frame);
        if (!sent) {
            return std::unexpected(sent.error());
        }
        auto reply = transport_->recv();
        if (!reply) {
            return std::unexpected(reply.error());
        }
        auto env = codec::decode_response(*reply);
        if (!env) {
            return std::unexpected(env.error());
        }
        return codec::parse_tools_list_result(*env);
    }

    auto call_tool(const tool_call_request& req)
        -> std::expected<tool_call_result, std::string> override {
        auto frame = codec::build_tools_call_request(next_id(), req);
        if (!frame) {
            return std::unexpected(frame.error());
        }
        auto sent = transport_->send(*frame);
        if (!sent) {
            return std::unexpected(sent.error());
        }
        auto reply = transport_->recv();
        if (!reply) {
            return std::unexpected(reply.error());
        }
        auto env = codec::decode_response(*reply);
        if (!env) {
            return std::unexpected(env.error());
        }
        return codec::parse_tools_call_result(*env);
    }

private:
    auto next_id() -> std::int64_t { return ++last_id_; }

    std::unique_ptr<transport> transport_;
    std::int64_t last_id_ = 0;
};

} // namespace

auto make_client(std::unique_ptr<transport> t) -> std::unique_ptr<client> {
    return std::make_unique<jsonrpc_client>(std::move(t));
}

} // namespace glove::mcp
