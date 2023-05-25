## custom_mutation for AFL++

cmake_minimum_required(VERSION 3.5.1)

project(SymSanMutator C CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -std=c++17 -mcx16 -march=native -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")

if (NOT LLVM_FOUND)
  message(FATAL_ERROR "You haven't install LLVM !")
endif()

if (NOT DEFINED AFLPP_PATH OR NOT AFLPP_PATH)
  message(FATAL_ERROR "AFL++ directory not defined !")
endif()

# Proto file
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS rgd.proto)
add_custom_target(proto ALL DEPENDS ${PROTO_SRCS} ${PROTO_SRCS})

add_subdirectory(jigsaw)
add_dependencies(jigsaw proto)

add_library(SymSanMutator SHARED
  symsan.cpp
  z3-solver.cpp
  jit-solver.cpp
  ${PROTO_SRCS}
  ${PROTO_HDRS}
)

target_include_directories(SymSanMutator PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
  ${AFLPP_PATH}/include
)

target_link_libraries(SymSanMutator
  ${PROTOBUF_LIBRARIES}
  tcmalloc
  z3
  jigsaw
)

install (TARGETS SymSanMutator DESTINATION ${SYMSAN_BIN_DIR})
