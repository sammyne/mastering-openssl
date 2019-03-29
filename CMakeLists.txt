cmake_minimum_required(VERSION 3.12)

PROJECT (openssl-hello-world)

INCLUDE_DIRECTORIES(
  /usr/include
  ./include
)

AUX_SOURCE_DIRECTORY(./encoding ENCODING)

ADD_LIBRARY(encoding SHARED ${ENCODING})

## sha

# SHA256
ADD_EXECUTABLE(sha256 sha/main.cpp)
TARGET_LINK_LIBRARIES(sha256 crypto encoding)

## END sha

## evp

FILE(GLOB EVP_SOURCES evp/*.cpp)

FOREACH( src ${EVP_SOURCES} )
  GET_FILENAME_COMPONENT( out ${src} NAME_WE )
  SET(out evp_${out})

  ADD_EXECUTABLE( ${out} ${src} )
  TARGET_LINK_LIBRARIES(${out} crypto encoding)
ENDFOREACH( src )

# SHA3-256
#ADD_EXECUTABLE(evp_sha3_256 evp/sha3_256.cpp)
#TARGET_LINK_LIBRARIES(evp_sha3_256 crypto encoding)

## END evp
