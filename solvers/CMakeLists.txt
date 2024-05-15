set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

## solvers
add_library(Z3Solver STATIC z3.cpp z3-ts.cpp)
target_compile_options(Z3Solver PRIVATE -stdlib=libc++)
target_include_directories(Z3Solver PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
install (TARGETS Z3Solver DESTINATION ${SYMSAN_LIB_DIR})

add_library(Fastgen STATIC fastgen.cpp)
target_compile_options(Fastgen PRIVATE -stdlib=libc++)
target_include_directories(Fastgen PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
install (TARGETS Fastgen DESTINATION ${SYMSAN_LIB_DIR})

## parser
add_library(z3parser STATIC z3-ts.cpp)
target_include_directories(z3parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)

## rgd-solver

add_subdirectory(jigsaw)

add_library(rgd-solver STATIC
    z3-solver.cpp
    jit-solver.cpp
    i2s-solver.cpp
)

target_include_directories(z3parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)

target_link_libraries(rgd-solver PRIVATE
    tcmalloc
    z3
    jigsaw
    profiler
)
