add_library(glove_run STATIC
    runner.cpp
)
add_library(glove::run ALIAS glove_run)

target_link_libraries(glove_run
    PUBLIC
        glove_options
        glove::container
        glove::kernel
        glove::mcp
        glove::policy
        glove::audit
        glove::net
)
target_include_directories(glove_run
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
