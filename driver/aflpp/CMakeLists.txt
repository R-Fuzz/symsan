## custom_mutation for AFL++

cmake_minimum_required(VERSION 3.5.1)

project(SymSanMutator C CXX)

find_package(Boost REQUIRED COMPONENTS container)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -mcx16 -march=native -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
if (ASAN_BUILD)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -lc++abi")

if (NOT LLVM_FOUND)
  message(FATAL_ERROR "You haven't install LLVM !")
endif()

if (NOT IS_DIRECTORY "${AFLPP_PATH}/include")
  message(FATAL_ERROR "Invalid AFL++ directory path!")
endif()

add_subdirectory(jigsaw)

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
  ${Boost_INCLUDE_DIRS}
)

target_link_libraries(SymSanMutator
  tcmalloc
  z3
  jigsaw
  profiler
  Boost::container
)
if (ASAN_BUILD)
  target_link_libraries(SymSanMutator
    ${LLVM_BINARY_DIR}/lib/clang/12.0.1/lib/linux/libclang_rt.asan-x86_64.a
  )
endif()

install (TARGETS SymSanMutator DESTINATION ${SYMSAN_BIN_DIR})
