cmake_minimum_required(VERSION 3.12)

PROJECT (openssl-hello-world)

SET(SSL /usr/local/ssl)
SET(CODEC ${PROJECT_SOURCE_DIR}/3rd_party/cppcodec)

#  /usr/include
INCLUDE_DIRECTORIES(
  ${CODEC}
  ${SSL}/include
  ${PROJECT_SOURCE_DIR}/include
)

LINK_DIRECTORIES(${SSL}/lib)

AUX_SOURCE_DIRECTORY(./encoding ENCODING)

ADD_LIBRARY(encoding SHARED ${ENCODING})

#${PROJECT_SOURCE_DIR}/crypto 
SET(MODULES 
  ${PROJECT_SOURCE_DIR}/ssl 
)

FOREACH( m ${MODULES} )
  GET_FILENAME_COMPONENT( moduleName ${m} NAME )
  MESSAGE( "* ${moduleName}" )

  FILE(GLOB submodules ${m}/*)  
  FOREACH( sub ${submodules} )
    #MESSAGE( "-- ${sub}")

    GET_FILENAME_COMPONENT( submoduleName ${sub} NAME )
    #MESSAGE( "--- ${submoduleName}")

    FILE(GLOB sources ${sub}/*.cpp)  
    FOREACH( src ${sources} )

      GET_FILENAME_COMPONENT( out ${src} NAME_WE )
      SET(out ${moduleName}_${submoduleName}_${out})
      #MESSAGE(${out})

      ADD_EXECUTABLE( ${out} ${src} )
      TARGET_LINK_LIBRARIES(${out} crypto ssl encoding)
    ENDFOREACH( src )

  ENDFOREACH( sub )

ENDFOREACH( m )