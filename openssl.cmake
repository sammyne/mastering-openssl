include(ExternalProject)

### OpenSSL 1.1.1b
ExternalProject_Add(OpenSSL 
        PREFIX openssl
        URL https://www.openssl.org/source/openssl-1.1.1b.tar.gz 
        URL_HASH SHA256=5c557b023230413dfb0756f3137a13e6d726838ccd1430888ad15bfb2b43ea4b 
        INSTALL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rd_party/openssl  
        CONFIGURE_COMMAND ./config --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl
        no-weak-ssl-ciphers enable-ec_nistp_64_gcc_128 
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