## custom_mutation for AFL++

cmake_minimum_required(VERSION 3.5.1)

project(SymSanMutator C CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -std=c++17 -mcx16 -march=native -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")

if (NOT LLVM_FOUND)
  message(FATAL_ERROR "You haven't install LLVM !")
endif()

if (NOT IS_DIRECTORY "${AFLPP_PATH}/include")
  message(FATAL_ERROR "Invalid AFL++ directory path!")
endif()

add_subdirectory(jigsaw)

add_subdirectory(jigsaw)
add_dependencies(jigsaw proto)

add_library(SymSanMutator SHARED
  symsan.cpp
  z3-solver.cpp
  jit-solver.cpp
  i2s-solver.cpp
)

target_include_directories(SymSanMutator PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
  ${AFLPP_PATH}/include
)

target_link_libraries(SymSanMutator
  tcmalloc
  z3
  jigsaw
  profiler
)

install (TARGETS SymSanMutator DESTINATION ${SYMSAN_BIN_DIR})
