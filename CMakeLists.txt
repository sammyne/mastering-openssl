cmake_minimum_required(VERSION 3.12)

PROJECT (openssl-hello-world)

INCLUDE_DIRECTORIES(
  /usr/include
)

ADD_EXECUTABLE(sha256 sha/main.cpp)

TARGET_LINK_LIBRARIES(sha256 crypto)