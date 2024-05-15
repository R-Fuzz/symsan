cmake_minimum_required(VERSION 3.5.1)

project(jigsaw CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -mcx16 -march=native -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
if (ASAN_BUILD)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

add_library(jigsaw STATIC
  gd.cc
  input.cc
  grad.cc
  jit.cc
)

target_include_directories(jigsaw PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../
)

target_link_libraries(jigsaw
  tcmalloc
  LLVM
)
