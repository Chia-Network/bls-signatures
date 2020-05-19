CMAKE_MINIMUM_REQUIRED(VERSION 3.14 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
  ${CMAKE_BINARY_DIR}/contrib/relic/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  )

# CMake 3.14+
include(FetchContent)

FetchContent_Declare(
  pybind11-src
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG        v2.5.0
)
FetchContent_MakeAvailable(pybind11-src)

pybind11_add_module(blspy ${CMAKE_CURRENT_SOURCE_DIR}/pythonbindings.cpp)

if (SODIUM_FOUND)
  target_link_libraries(blspy PRIVATE blstmp relic_s sodium)
else()
  target_link_libraries(blspy PRIVATE blstmp relic_s)
endif()
