cmake_minimum_required(VERSION 3.20)

project(ecdsa)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)

aux_source_directory(./ srcs)

foreach(d ${srcs})
  get_filename_component( out ${d} NAME_WE )
  # MESSAGE(${out})

  add_executable(${out} ${d})
  target_link_libraries(${out} crypto)
  add_dependencies(${out} OpenSSL)
endforeach(d)
