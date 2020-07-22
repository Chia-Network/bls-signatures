CMAKE_MINIMUM_REQUIRED(VERSION 3.14 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)

# CMake 3.14+
include(FetchContent)

FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG        v2.5.0
)
FetchContent_MakeAvailable(pybind11 chia-relic)


include_directories(
  ${INCLUDE_DIRECTORIES}
  ${chia-relic_SOURCE_DIR}/include
  ${chia-relic_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  ${GMP_INCLUDES}
  )

pybind11_add_module(blspy ${CMAKE_CURRENT_SOURCE_DIR}/pythonbindings.cpp)

if (SODIUM_FOUND)
  message("SODIUM_FOUND in python-bindings/CMakeLists.txt")
  set(BLSALLOC_SODIUM "1" CACHE STRING "")
  set(SODIUM_STATIC "1" CACHE STRING "")
  target_compile_definitions(blstmp PRIVATE BLSALLOC_SODIUM=1 SODIUM_STATIC=1)
  target_link_libraries(blspy PRIVATE blstmp relic_s sodium)
else()
  target_link_libraries(blspy PRIVATE blstmp relic_s)
endif()
