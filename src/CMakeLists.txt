CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)

file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)
source_group("SrcHeaders" FILES ${HEADERS})

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
  ${CMAKE_BINARY_DIR}/contrib/relic/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  )

add_library(bls ${HEADERS}
  ${CMAKE_CURRENT_SOURCE_DIR}/extendedpublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/extendedprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chaincode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blssignature.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blspublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blsprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/aggregationinfo.cpp
)

add_executable(runtest test.cpp)
add_executable(runbench test-bench.cpp)

if (SODIUM_FOUND)
  target_link_libraries(runtest bls relic_s sodium)
  target_link_libraries(runbench bls relic_s sodium)
else()
  target_link_libraries(runtest bls relic_s)
  target_link_libraries(runbench bls relic_s)
endif()
