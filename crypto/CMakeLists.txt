cmake_minimum_required(VERSION 3.20)

project(crypto)

SET(MODULES ec evp sha)

foreach(m ${MODULES})
  add_subdirectory(${m})
  message("crypto> add ${m}")
endforeach(m)
