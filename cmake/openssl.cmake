include(ExternalProject)

# OpenSSL 1.1.1k
# CONFIGURE_COMMAND ./config --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl
ExternalProject_Add(OpenSSL 
        PREFIX openssl
        URL https://www.openssl.org/source/openssl-1.1.1k.tar.gz 
        URL_HASH SHA256=892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5 
        INSTALL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssl  
        CONFIGURE_COMMAND ./config --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(OpenSSL INSTALL_DIR)
#MESSAGE("--- ${INSTALL_DIR}")

# set global env to referenced by others
set(OPENSSL_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(OPENSSL_LINK_DIRECTORIES ${INSTALL_DIR}/lib)

# create the ${INSTALL_DIR}/include directory
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(openssl-crypto-static STATIC IMPORTED GLOBAL)
set_property(TARGET openssl-crypto-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET openssl-crypto-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

add_library(openssl-ssl-static STATIC IMPORTED GLOBAL)
set_property(TARGET openssl-ssl-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET openssl-ssl-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)