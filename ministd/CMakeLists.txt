
file(GLOB_RECURSE srcs src/*.cc)

add_library(ministd SHARED ${srcs})
