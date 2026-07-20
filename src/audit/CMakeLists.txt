add_library(glove_audit STATIC
    memory_sink.cpp
    jsonl_sink.cpp
    audit_client.cpp
)
add_library(glove::audit ALIAS glove_audit)

target_link_libraries(glove_audit
    PUBLIC
        glove_options
        glove::mcp
)
target_link_libraries(glove_audit PRIVATE glaze::glaze)
target_include_directories(glove_audit
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
