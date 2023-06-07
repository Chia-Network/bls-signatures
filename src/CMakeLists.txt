file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

add_compile_options(-fno-builtin)
add_compile_options(-fPIC)
add_compile_options(-Wall)
add_compile_options(-Wextra)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    add_compile_options(-mno-avx)
endif ()
add_compile_options(-D__BLST_PORTABLE__)

add_library(bls
  ${HEADERS}
  ${CMAKE_CURRENT_SOURCE_DIR}/privatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/elements.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/schemes.cpp
  ${blst_SOURCE_DIR}/src/server.c
  ${blst_SOURCE_DIR}/build/assembly.S
)

target_include_directories(bls
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${blst_SOURCE_DIR}
)

target_compile_definitions(bls
  PRIVATE
    BLSALLOC_SODIUM=1
)

target_link_libraries(bls
  PUBLIC
    sodium
)

if(WITH_COVERAGE)
  target_compile_options(bls PRIVATE --coverage)
  target_link_options(bls PRIVATE --coverage)
endif()

install(DIRECTORY ${blst_SOURCE_DIR}/include/ DESTINATION include/chiabls)
install(DIRECTORY ${blst_BINARY_DIR}/include/ DESTINATION include/chiabls)
install(FILES ${HEADERS} DESTINATION include/chiabls)
install(FILES $<TARGET_FILE:bls> DESTINATION lib)

if(BUILD_BLS_TESTS)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.3.2
  )
  FetchContent_MakeAvailable(Catch2)
  find_package(Threads REQUIRED)
  add_executable(runtest test.cpp)
  if(EMSCRIPTEN)
    target_link_options(runtest PRIVATE "-sEXPORTED_FUNCTIONS=_malloc")
  endif()
  target_link_libraries(runtest
    PRIVATE
      bls
      Catch2::Catch2
      Threads::Threads
  )
  if(WITH_COVERAGE)
    target_compile_options(runtest PRIVATE --coverage)
    target_link_options(runtest PRIVATE --coverage)
  endif()
endif()

if(BUILD_BLS_BENCHMARKS)
  add_executable(runbench test-bench.cpp)
  target_link_libraries(runbench PRIVATE bls)
endif()
