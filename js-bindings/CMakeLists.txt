CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
  ${CMAKE_BINARY_DIR}/contrib/relic/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  )

add_executable(blsjs ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/jsbindings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/wrappers/PrivateKeyWrapper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/wrappers/SignatureWrapper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/wrappers/PrivateKeyWrapper.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../js-bindings/wrappers/SignatureWrapper.cpp
)

if (SODIUM_FOUND)
  target_link_libraries(blsjs PRIVATE blstmp relic_s sodium)
else()
  target_link_libraries(blsjs PRIVATE blstmp relic_s)
endif()

set_target_properties(blsjs PROPERTIES LINK_FLAGS "--bind -s WASM=0")
