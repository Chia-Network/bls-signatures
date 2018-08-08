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

set(C_LIB ${CMAKE_BINARY_DIR}/libbls.a)

add_library(bls ${CMAKE_CURRENT_SOURCE_DIR}/chaincode.cpp)

add_library(blstmp ${HEADERS}
  ${CMAKE_CURRENT_SOURCE_DIR}/extendedpublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/extendedprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chaincode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blssignature.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blspublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/blsprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/aggregationinfo.cpp
)

set(OPREFIX object_)
find_library(GMP_NAME NAMES libgmp.a gmp)
find_library(SODIUM_NAME NAMES libsodium.a sodium)

set(LIBRARIES_TO_COMBINE
      COMMAND mkdir ${OPREFIX}$<TARGET_NAME:blstmp> || true && cd ${OPREFIX}$<TARGET_NAME:blstmp> &&  ar -x $<TARGET_FILE:blstmp>
      COMMAND mkdir ${OPREFIX}$<TARGET_NAME:relic_s> || true && cd ${OPREFIX}$<TARGET_NAME:relic_s> &&  ar -x $<TARGET_FILE:relic_s>
)

if (GMP_FOUND)
  list(APPEND LIBRARIES_TO_COMBINE COMMAND mkdir ${OPREFIX}gmp || true && cd ${OPREFIX}gmp &&  ar -x ${GMP_NAME})
endif()
if (SODIUM_FOUND)
  list(APPEND LIBRARIES_TO_COMBINE COMMAND mkdir ${OPREFIX}sodium || true && cd ${OPREFIX}sodium &&  ar -x ${SODIUM_NAME})
endif()

add_custom_target(combined_custom
        ${LIBRARIES_TO_COMBINE}
        COMMAND ar -rs ${C_LIB} ${OPREFIX}*/*.o
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS blstmp relic_s
        )

add_library(combined STATIC IMPORTED GLOBAL)
add_dependencies(combined combined_custom)

target_link_libraries(bls combined)

set_target_properties(combined
        PROPERTIES
        IMPORTED_LOCATION ${C_LIB}
        )

add_executable(runtest test.cpp)
add_executable(runbench test-bench.cpp)

if (SODIUM_FOUND)
  target_link_libraries(runtest blstmp relic_s sodium)
  target_link_libraries(runbench blstmp relic_s sodium)
else()
  target_link_libraries(runtest blstmp relic_s)
  target_link_libraries(runbench blstmp relic_s)
endif()
