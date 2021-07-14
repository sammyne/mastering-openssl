cmake_minimum_required(VERSION 3.20)

project(ssl)

set(MODULES tls13)

foreach(m ${MODULES})
  add_subdirectory(tls13)
  message("ssl> add ${m}")
endforeach(m)