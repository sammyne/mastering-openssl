project(AEAD)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} srcs)

foreach(d ${srcs})
  get_filename_component( out ${d} NAME_WE )
  set(out "${PROJECT_NAME}-${out}")

  add_executable(${out} ${d})
  target_link_libraries(${out} openssl-crypto ministd)
  add_dependencies(${out} OpenSSL)
endforeach(d)
