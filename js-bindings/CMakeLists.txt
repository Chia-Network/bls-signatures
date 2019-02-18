CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 11)

include_directories(
        ${INCLUDE_DIRECTORIES}
        ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
        ${CMAKE_BINARY_DIR}/contrib/relic/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
)

file(GLOB_RECURSE WRAP_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/wrappers/*.h)
file(GLOB_RECURSE WRAP_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/wrappers/*.cpp)

add_executable(blsjs ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/jsbindings.cpp
        ${WRAP_HEADERS} ${WRAP_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/helpers.h ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/helpers.cpp
        )

if (SODIUM_FOUND)
    target_link_libraries(blsjs PRIVATE blstmp relic_s sodium)
else ()
    target_link_libraries(blsjs PRIVATE blstmp relic_s)
endif ()

set_target_properties(blsjs PROPERTIES LINK_FLAGS "--bind -s WASM=0 -s DISABLE_EXCEPTION_CATCHING=0")
