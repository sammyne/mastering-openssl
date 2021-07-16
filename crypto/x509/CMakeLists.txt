cmake_minimum_required(VERSION 3.20)

project(x509)

aux_source_directory(./ srcs)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)

foreach(d ${srcs})
  get_filename_component( out ${d} NAME_WE )
  set(out "${PROJECT_NAME}-${out}")
  # MESSAGE(${out})

  add_executable(${out} ${d})
  target_link_libraries(${out} crypto)
  add_dependencies(${out} OpenSSL)
endforeach(d)
