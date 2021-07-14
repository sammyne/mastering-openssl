CMAKE_MINIMUM_REQUIRED(VERSION 3.20)

project(ec)

aux_source_directory(./ DEMOS)

foreach(d ${DEMOS})
  get_filename_component( out ${d} NAME_WE )
  # MESSAGE(${out})

  add_executable(${out} ${d})
  target_link_libraries(${out} crypto)
  add_dependencies(${out} OpenSSL)
endforeach(d)
