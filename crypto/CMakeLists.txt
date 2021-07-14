cmake_minimum_required(VERSION 3.20)

project(crypto)

#set(MODULES ec evp sha)
set(MODULES ecdsa)

foreach(m ${MODULES})
  add_subdirectory(${m})
  message("crypto> add ${m}")
endforeach(m)
