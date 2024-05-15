## custom_mutation for AFL++

cmake_minimum_required(VERSION 3.5.1)

project(SymSanMutator C CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -mcx16 -march=native -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
if (ASAN_BUILD)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

if (NOT IS_DIRECTORY "${AFLPP_PATH}/include")
  message(FATAL_ERROR "Invalid AFL++ directory path!")
endif()

add_library(SymSanMutator SHARED symsan.cpp )
target_include_directories(SymSanMutator PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
  ${AFLPP_PATH}/include
)
target_link_libraries(SymSanMutator
  launcher
  rgd-parser
  rgd-solver
)
if (ASAN_BUILD)
  target_link_libraries(SymSanMutator
    ${LLVM_BINARY_DIR}/lib/clang/12.0.1/lib/linux/libclang_rt.asan-x86_64.a
  )
endif()

install (TARGETS SymSanMutator DESTINATION ${SYMSAN_BIN_DIR})
