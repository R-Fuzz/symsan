set(CMAKE_POSITION_INDEPENDENT_CODE ON)

## custom model
# add_library(ZlibRt STATIC zlib_func.c)
# install (TARGETS ZlibRt DESTINATION ${SYMSAN_LIB_DIR})
install (FILES "zlib_abilist.txt" DESTINATION ${SYMSAN_LIB_DIR})
