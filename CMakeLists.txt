CMAKE_MINIMUM_REQUIRED(VERSION 3.14.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release"
    CACHE STRING "Possible values are empty, Debug, Release, RelWithDebInfo, MinSizeRel, ..."
    FORCE
  )
endif()

project(BLS C CXX ASM)

set(BUILD_BLS_PYTHON_BINDINGS "1" CACHE STRING "")
set(BUILD_BLS_TESTS "1" CACHE STRING "")
set(BUILD_BLS_BENCHMARKS "1" CACHE STRING "")

message(STATUS "Build python bindings: ${BUILD_BLS_PYTHON_BINDINGS}")
message(STATUS "Build tests: ${BUILD_BLS_TESTS}")
message(STATUS "Build benchmarks: ${BUILD_BLS_BENCHMARKS}")

# Add path for custom modules
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules
)

include(FetchContent)

FetchContent_Declare(Sodium
  GIT_REPOSITORY https://github.com/AmineKhaldi/libsodium-cmake.git
  # Latest commit at the moment this was added here
  # Anchored to libsodium v1.0.18
  GIT_TAG f73a3fe1afdc4e37ac5fe0ddd401bf521f6bba65
)
set(SODIUM_PCH "on" CACHE STRING "")
set(SODIUM_DISABLE_TESTS "on" CACHE STRING "")
set(SODIUM_CHIA_MINIMAL "on" CACHE STRING "")
FetchContent_MakeAvailable(Sodium)

set(BLST_GIT_TAG "origin/master")
set(BLST_REPOSITORY "https://github.com/supranational/blst")

message(STATUS "blst will be built from: ${BLST_GIT_TAG} and repository ${BLST_REPOSITORY}")

FetchContent_Declare(
  blst
  GIT_REPOSITORY ${BLST_REPOSITORY}
  GIT_TAG ${BLST_GIT_TAG}
)

FetchContent_MakeAvailable(blst)

add_subdirectory(src)

if(EMSCRIPTEN)
  add_subdirectory(js-bindings)
else()
  # emscripten can't build python bindings, it produces only javascript
  # add_subdirectory(contrib/pybind11)
  if(BUILD_BLS_PYTHON_BINDINGS)
    add_subdirectory(python-bindings)
  endif()
endif()
