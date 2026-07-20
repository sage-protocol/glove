add_library(glove_mcp STATIC
    in_memory_transport.cpp
    stdio_transport.cpp
    codec.cpp
    client.cpp
    jsonrpc_client.cpp
    lazy_init.cpp
)
add_library(glove::mcp ALIAS glove_mcp)

target_link_libraries(glove_mcp PUBLIC glove_options)
target_link_libraries(glove_mcp PRIVATE glaze::glaze)
target_include_directories(glove_mcp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
