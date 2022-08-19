set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -g")

## solvers
add_library(Z3Solver STATIC z3.cpp)
target_include_directories(Z3Solver PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
install (TARGETS Z3Solver DESTINATION ${SYMSAN_LIB_DIR})

add_library(Fastgen STATIC fastgen.cpp)
target_include_directories(Fastgen PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
install (TARGETS Fastgen DESTINATION ${SYMSAN_LIB_DIR})
