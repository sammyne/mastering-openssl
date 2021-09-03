cmake_minimum_required(VERSION 3.13)

PROJECT (openssl-hello-world)

set(CMAKE_CXX_STANDARD 17)

# 3rd_party dependencies
include(cmake/openssl.cmake)

set(ministdDir ${CMAKE_CURRENT_SOURCE_DIR}/ministd)

include_directories(
  ${OPENSSL_INCLUDE_DIRECTORIES}
  ${ministdDir}/include
)

add_subdirectory(${ministdDir})

#add_subdirectory(ssl)
add_subdirectory(crypto)
