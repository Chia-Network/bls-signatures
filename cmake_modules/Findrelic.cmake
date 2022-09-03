# Try to find the RELIC library
# https://reliclib.org/
#
# This module supports requiring a minimum version, e.g. you can do
#   find_package(RELIC 6.0.0)
# to require version 6.0.0 to newer of RELIC.
#
# Once done this will define
#
#  RELIC_FOUND - system has RELIC lib with correct version
#  RELIC_INCLUDES - the RELIC include directory
#  RELIC_LIBRARIES - the RELIC library
#  RELIC_VERSION - RELIC version
#
# Copyright (c) 2016 Jack Poulson, <jack.poulson@gmail.com>
# Redistribution and use is allowed according to the terms of the BSD license.

find_path(RELIC_INCLUDES NAMES relic/relic_conf.h PATHS $ENV{RELICDIR} ${INCLUDE_INSTALL_DIR})

# Set RELIC_FIND_VERSION to 5.1.0 if no minimum version is specified
if(NOT RELIC_FIND_VERSION)
  if(NOT RELIC_FIND_VERSION_MAJOR)
    set(RELIC_FIND_VERSION_MAJOR 0)
  endif()
  if(NOT RELIC_FIND_VERSION_MINOR)
    set(RELIC_FIND_VERSION_MINOR 5)
  endif()
  if(NOT RELIC_FIND_VERSION_PATCH)
    set(RELIC_FIND_VERSION_PATCH 0)
  endif()
  set(RELIC_FIND_VERSION
    "${RELIC_FIND_VERSION_MAJOR}.${RELIC_FIND_VERSION_MINOR}.${RELIC_FIND_VERSION_PATCH}")
endif()

set(RELIC_INCLUDES ${RELIC_INCLUDES}/relic)
message("RELIC PATH: ${RELIC_INCLUDES}")
message("RELIC VERSION: ${RELIC_FIND_VERSION}")

message("RELIC_INCLUDES=${RELIC_INCLUDES}")
if(RELIC_INCLUDES)
  # Since the RELIC version macros may be in a file included by relic.h of the form
  # relic-.*[_]?.*.h (e.g., relic-x86_64.h), we search each of them.
  file(GLOB RELIC_HEADERS "${RELIC_INCLUDES}/relic_conf.h" "${RELIC_INCLUDES}/relic_*.h")
  set(RELIC_VERSION 0.5.0)
  # Check whether found version exists and exceeds the minimum requirement
  if(NOT RELIC_VERSION)
    set(RELIC_VERSION_OK FALSE)
    message(STATUS "RELIC version was not detected")
  elseif(${RELIC_VERSION} VERSION_LESS ${RELIC_FIND_VERSION})
    set(RELIC_VERSION_OK FALSE)
    message(STATUS "RELIC version ${RELIC_VERSION} found in ${RELIC_INCLUDES}, "
                   "but at least version ${RELIC_FIND_VERSION} is required")
  else()
    set(RELIC_VERSION_OK TRUE)
  endif()
endif()

if(STBIN)
  set(_relic_lib_name librelic.a)
else()
  set(_relic_lib_name librelic.so)
endif()

find_library(RELIC_LIBRARIES
  NAMES
    ${_relic_lib_name} relic.lib librelic-10 librelic relic librelic_s.a librelic.so
  PATHS
    $ENV{RELICDIR} ${LIB_INSTALL_DIR}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(relic DEFAULT_MSG
                                  RELIC_INCLUDES RELIC_LIBRARIES RELIC_VERSION_OK)
get_filename_component(RELIC_LIB ${RELIC_LIBRARIES} DIRECTORY)
mark_as_advanced(RELIC_LIB RELIC_INCLUDES RELIC_LIBRARIES)
