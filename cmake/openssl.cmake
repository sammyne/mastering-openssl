include(ExternalProject)

# OpenSSL 1.1.1k
ExternalProject_Add(OpenSSL 
  PREFIX openssl
  DOWNLOAD_COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/resync_openssl.sh <SOURCE_DIR>
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/_openssl
  INSTALL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssl
  CONFIGURE_COMMAND ./config --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl no-shared
  BUILD_COMMAND make -j
  INSTALL_COMMAND make install_sw
  BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(OpenSSL INSTALL_DIR)

# set global env to referenced by others
set(OPENSSL_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(OPENSSL_LINK_DIRECTORIES ${INSTALL_DIR}/lib)

# create the ${INSTALL_DIR}/include directory
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(openssl-crypto STATIC IMPORTED GLOBAL)
set_property(TARGET openssl-crypto PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET openssl-crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET openssl-crypto PROPERTY INTERFACE_LINK_LIBRARIES pthread dl)

add_library(openssl-ssl STATIC IMPORTED GLOBAL)
set_property(TARGET openssl-ssl PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET openssl-ssl PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET openssl-crypto PROPERTY INTERFACE_LINK_LIBRARIES pthread dl)
