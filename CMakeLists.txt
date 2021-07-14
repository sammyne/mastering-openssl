cmake_minimum_required(VERSION 3.20)

PROJECT (openssl-hello-world)

set(CMAKE_CXX_STANDARD 17)

# 3rd_party dependencies
include(cmake/openssl.cmake)
include(cmake/cppcodec.cmake)

include_directories(
  ${CPPCODEC_INCLUDE_DIRECTORIES}
  ${OPENSSL_INCLUDE_DIRECTORIES}
)

link_directories(${OPENSSL_LINK_DIRECTORIES})

#add_subdirectory(ssl)
add_subdirectory(crypto)