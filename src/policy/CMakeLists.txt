add_library(glove_policy STATIC
    allow_list_engine.cpp
    jsonpath_engine.cpp
    policy_client.cpp
)
add_library(glove::policy ALIAS glove_policy)

target_link_libraries(glove_policy
    PUBLIC
        glove_options
        glove::mcp
)
# glaze drives the JSON parsing in jsonpath_engine. PRIVATE — public
# headers stay glaze-free.
target_link_libraries(glove_policy PRIVATE glaze::glaze)
target_include_directories(glove_policy
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
