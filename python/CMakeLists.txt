CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)
file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/../src/*.h)
source_group("SrcHeaders" FILES ${HEADERS})

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
  ${CMAKE_BINARY_DIR}/contrib/relic/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  )

pybind11_add_module(blspy
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/extendedpublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/extendedprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/chaincode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/blssignature.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/blspublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/blsprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/aggregationinfo.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pythonbindings.cpp)

if (SODIUM_FOUND)
  target_link_libraries(blspy PRIVATE relic_s sodium)
else()
  target_link_libraries(blspy PRIVATE relic_s)
endif()
