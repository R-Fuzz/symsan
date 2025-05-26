set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

add_library(Fastgen STATIC fastgen.cpp)
target_compile_options(Fastgen PRIVATE -stdlib=libc++)
target_include_directories(Fastgen PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
install (TARGETS Fastgen DESTINATION ${SYMSAN_LIB_DIR})
