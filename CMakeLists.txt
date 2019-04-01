cmake_minimum_required(VERSION 3.12)

PROJECT (openssl-hello-world)

INCLUDE_DIRECTORIES(
  /usr/include
  ${PROJECT_SOURCE_DIR}/include
)

AUX_SOURCE_DIRECTORY(./encoding ENCODING)

ADD_LIBRARY(encoding SHARED ${ENCODING})

SET(MODULES 
  ${PROJECT_SOURCE_DIR}/crypto 
)

FOREACH( m ${MODULES} )
  GET_FILENAME_COMPONENT( moduleName ${m} NAME )
  #MESSAGE( "* ${moduleName}" )

  FILE(GLOB submodules ${m}/*)  
  FOREACH( sub ${submodules} )
    #MESSAGE( "-- ${sub}")

    GET_FILENAME_COMPONENT( submoduleName ${sub} NAME )
    #MESSAGE( "--- ${submoduleName}")

    FILE(GLOB sources ${sub}/*)  
    FOREACH( src ${sources} )

      GET_FILENAME_COMPONENT( out ${src} NAME_WE )
      SET(out ${moduleName}_${submoduleName}_${out})
      #MESSAGE(${out})

      ADD_EXECUTABLE( ${out} ${src} )
      TARGET_LINK_LIBRARIES(${out} crypto encoding)
    ENDFOREACH( src )

  ENDFOREACH( sub )

ENDFOREACH( m )