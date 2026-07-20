add_library(glove_term STATIC
    null_terminal.cpp
    factory.cpp
)
add_library(glove::term ALIAS glove_term)

target_link_libraries(glove_term PUBLIC glove_options)
target_include_directories(glove_term
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

if(GLOVE_WITH_GHOSTTY)
    # The libghostty C library is expected on the include and link paths.
    # Once we vendor it under third_party/ghostty/ this find_package call will
    # pick it up; for now an explicit GHOSTTY_ROOT cache var is honored.
    find_library(GHOSTTY_LIB
        NAMES ghostty
        HINTS ${GHOSTTY_ROOT}/lib
    )
    find_path(GHOSTTY_INCLUDE_DIR
        NAMES ghostty/vt.h
        HINTS ${GHOSTTY_ROOT}/include
    )
    if(NOT GHOSTTY_LIB OR NOT GHOSTTY_INCLUDE_DIR)
        message(FATAL_ERROR
            "GLOVE_WITH_GHOSTTY=ON but libghostty not found. "
            "Set -DGHOSTTY_ROOT=<install-prefix>.")
    endif()
    target_sources(glove_term PRIVATE ghostty_terminal.cpp)
    target_include_directories(glove_term PRIVATE ${GHOSTTY_INCLUDE_DIR})
    target_link_libraries(glove_term PRIVATE ${GHOSTTY_LIB})
    target_compile_definitions(glove_term PRIVATE GLOVE_WITH_GHOSTTY=1)
endif()
