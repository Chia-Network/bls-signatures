CMAKE_MINIMUM_REQUIRED(VERSION 3.11 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  )

# CMake 3.11+
include(FetchContent)

FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG        v2.5.0
)
FetchContent_Declare(
  chia-relic
  GIT_REPOSITORY https://github.com/Chia-Network/relic
  GIT_TAG        origin/master
)
FetchContent_MakeAvailable(pybind11)
FetchContent_GetProperties(chia-relic)
if (NOT chia-relic-src_POPULATED)
    FetchContent_Populate(chia-relic)
endif ()

add_subdirectory(${chia-relic_SOURCE_DIR} ${chia-relic_BINARY_DIR})

pybind11_add_module(blspy ${CMAKE_CURRENT_SOURCE_DIR}/pythonbindings.cpp)

if (SODIUM_FOUND)
  target_link_libraries(blspy PRIVATE blstmp relic_s sodium)
else()
  target_link_libraries(blspy PRIVATE blstmp relic_s)
endif()
