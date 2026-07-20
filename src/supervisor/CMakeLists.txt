add_library(glove_supervisor STATIC
    library_bundle.cpp
    path_alias.cpp
    session_plan.cpp
)
add_library(glove::supervisor ALIAS glove_supervisor)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(glove_supervisor PRIVATE
        linux/ephemeral_copy.cpp
        linux/session_filesystem.cpp
    )
endif()

target_link_libraries(glove_supervisor PUBLIC glove_options PRIVATE glaze::glaze glove_digest)
target_include_directories(glove_supervisor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
