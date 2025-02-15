cmake_minimum_required(VERSION 3.10)
project(HashSetRT LANGUAGES C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(HashSetRT STATIC hashmap.c hashset.c)
target_include_directories(HashSetRT PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS HashSetRT DESTINATION ${SYMSAN_LIB_DIR})
