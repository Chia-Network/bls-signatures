file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

list(APPEND bls_sources
  ${HEADERS}
  privatekey.cpp
  bls.cpp
  elements.cpp
  schemes.cpp
  ${blst_SOURCE_DIR}/src/server.c
)

if(MSVC)
  list(APPEND bls_sources
    ${blst_SOURCE_DIR}/build/win64/add_mod_256-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/add_mod_384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/add_mod_384x384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/ct_inverse_mod_256-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/ct_is_square_mod_384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/ctq_inverse_mod_384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/ctx_inverse_mod_384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/div3w-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/mulq_mont_256-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/mulq_mont_384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/mulx_mont_256-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/mulx_mont_384-x86_64.asm
    ${blst_SOURCE_DIR}/build/win64/sha256-x86_64.asm
  )
else()
  list(APPEND bls_sources
    ${blst_SOURCE_DIR}/build/assembly.S
  )
  add_compile_options(-fno-builtin)
  add_compile_options(-fPIC)
  add_compile_options(-Wall)
  add_compile_options(-Wextra)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    add_compile_options(-mno-avx)
  endif()
endif()

add_library(bls ${bls_sources})
target_include_directories(bls PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${blst_SOURCE_DIR}
)
target_compile_definitions(bls PRIVATE __BLST_PORTABLE__ BLSALLOC_SODIUM=1)
target_link_libraries(bls PUBLIC sodium)

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
    GIT_TAG v3.3.2
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
