cmake_minimum_required(VERSION 3.12)

PROJECT (openssl-hello-world)

INCLUDE_DIRECTORIES(
  /usr/include
  ./include
)

AUX_SOURCE_DIRECTORY(./encoding ENCODING)

ADD_LIBRARY(encoding SHARED ${ENCODING})

SET(MODULES 
  ${PROJECT_SOURCE_DIR}/sha 
  ${PROJECT_SOURCE_DIR}/evp 
)

FOREACH( m ${MODULES} )
  FILE(GLOB SOURCES ${m}/*.cpp)  

  # extra the module prefix
  GET_FILENAME_COMPONENT( mp ${m} NAME )

  FOREACH( src ${SOURCES} )
    GET_FILENAME_COMPONENT( out ${src} NAME_WE )
    SET(out ${mp}_${out})

    ADD_EXECUTABLE( ${out} ${src} )
    TARGET_LINK_LIBRARIES(${out} crypto encoding)
  ENDFOREACH( src )

ENDFOREACH( m )