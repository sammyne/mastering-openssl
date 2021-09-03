cmake_minimum_required(VERSION 3.13)

project(crypto)

#set(MODULES ec evp sha)
#set(MODULES ecdsa sm2 sm3 x509)
#set(MODULES sm2)
set(MODULES aead)

foreach(m ${MODULES})
  add_subdirectory(${m})
  message("crypto> add ${m}")
endforeach(m)
