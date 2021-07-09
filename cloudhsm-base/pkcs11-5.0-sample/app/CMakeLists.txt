cmake_minimum_required(VERSION 2.8)
project(aws-cloudhsm-pkcs11-examples)

SET(ORGANIZATION_NAME "Amazon.com, Inc.")
IF (MSVC)
  SET(CMAKE_C_FLAGS "/W3 /WX /J /std:c11 /Wv:18")
ELSE()
  SET(CMAKE_C_FLAGS "-Wall -Werror -Wno-pointer-sign -fno-signed-char -std=c99")
ENDIF()

ENABLE_TESTING()

include_directories(include/pkcs11/v2.40)
include_directories(include/gopt)
include_directories(src/common)

add_subdirectory(src/common)
add_subdirectory(src/encrypt)
add_subdirectory(src/mechanism_info)

IF(LINUX)
ENDIF()
