set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O3 -Wno-format")

# Fastgen backend (dfsan symbolic execution + out-of-process solving)
add_library(Fastgen STATIC fastgen.cpp solver_common.cpp forkserver.cpp)
target_include_directories(Fastgen PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Thoroupy backend (ucsan under-constrained execution + fastgen dfsan callbacks)
add_library(Thoroupy STATIC thoroupy.cpp fastgen.cpp solver_common.cpp)
target_include_directories(Thoroupy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
    ${CMAKE_CURRENT_SOURCE_DIR}
)

install (TARGETS Fastgen Thoroupy DESTINATION ${SYMSAN_LIB_DIR})
