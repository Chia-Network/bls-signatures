CMAKE_MINIMUM_REQUIRED(VERSION 3.14.0 FATAL_ERROR)

project(blsflutter)
include(FetchContent)
FetchContent_Declare(
  bls
  GIT_REPOSITORY https://github.com/MegaGrindStone/bls-signatures.git
  GIT_TAG origin/flutter-bindings
)
FetchContent_MakeAvailable(bls)

add_library(blsflutter
        SHARED
        ../ios/bls/utils.cpp
        ../ios/bls/blschia.cpp
        ../ios/bls/elements.cpp
        ../ios/bls/privatekey.cpp
        ../ios/bls/schemes.cpp
)

target_include_directories(blsflutter
  PUBLIC
    ${bls_SOURCE_DIR}/include/chiabls
    ${bls_BINARY_DIR}/include/chiabls
)

target_link_libraries(blsflutter PRIVATE bls)