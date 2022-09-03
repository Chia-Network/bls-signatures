
file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

add_library(bls
  ${HEADERS}
  ${CMAKE_CURRENT_SOURCE_DIR}/privatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/elements.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/schemes.cpp
)

target_include_directories(bls
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    $<$<BOOL:${GMP_FOUND}>:${GMP_INCLUDES}>
    $<$<BOOL:${RELIC_FOUND}>:${RELIC_INCLUDES}>
    $<$<BOOL:${RELIC_FOUND}>:${RELIC_LIBRARIES}>
    ${relic_SOURCE_DIR}/include
    ${relic_BINARY_DIR}/include
)

target_compile_definitions(bls
  PRIVATE
    BLSALLOC_SODIUM=1
)

target_link_libraries(bls
  PUBLIC
    relic_s
    sodium
)

if(BUILD_LOCAL)
    install(DIRECTORY ${RELIC_INCLUDES} DESTINATION include/chiabls)
    install(DIRECTORY ${RELIC_LIB} DESTINATION include/chiabls)
else()
    install(DIRECTORY ${relic_SOURCE_DIR}/include/ DESTINATION include/chiabls)
    install(DIRECTORY ${relic_BINARY_DIR}/include/ DESTINATION include/chiabls)
endif()
install(FILES ${HEADERS} DESTINATION include/chiabls)
install(FILES $<TARGET_FILE:bls> DESTINATION lib)

if(BUILD_BLS_TESTS)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.0.0-preview5
  )
  FetchContent_MakeAvailable(Catch2)
  add_executable(runtest test.cpp)
  target_link_libraries(runtest PRIVATE bls Catch2::Catch2)
endif()

if(BUILD_BLS_BENCHMARKS)
  add_executable(runbench test-bench.cpp)
  target_link_libraries(runbench PRIVATE bls)
endif()
