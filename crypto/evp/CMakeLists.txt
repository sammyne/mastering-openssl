cmake_minimum_required(VERSION 3.20)

project(evp)

aux_source_directory(./ DEMOS)

foreach(d ${DEMOS})
  get_filename_component( out ${d} NAME_WE )
  # MESSAGE(${out})

  add_executable(${out} ${d})
  target_link_libraries(${out} crypto)
  add_dependencies(${out} OpenSSL)
endforeach(d)
