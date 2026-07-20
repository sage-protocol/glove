#pragma once

#include "glove/mcp/client.hpp"
#include "glove/mcp/transport.hpp"

#include <memory>

namespace glove::mcp::testing {

// Codec-free client used by tests that only want to exercise the transport
// boundary. Both list_tools() and call_tool() drive the transport but report
// transport_error as the result. Not intended for production use.
auto make_stub_client_for_tests(std::unique_ptr<transport> t) -> std::unique_ptr<client>;

} // namespace glove::mcp::testing
