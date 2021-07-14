include(ExternalProject)

# cppcodec
SET(CPPCODEC ${CMAKE_CURRENT_SOURCE_DIR}/third-party/cppcodec)

ExternalProject_Add(cppcodec 
  PREFIX cppcodec
  GIT_REPOSITORY https://github.com/tplgy/cppcodec.git 
  GIT_TAG bd6ddf95129e769b50ef63e0f558fa21364f3f65 
  CMAKE_ARGS -D CMAKE_INSTALL_PREFIX=${CPPCODEC}  
  BUILD_IN_SOURCE 1)

# set global env to referenced by others
set(CPPCODEC_INCLUDE_DIRECTORIES ${CPPCODEC}/include)
