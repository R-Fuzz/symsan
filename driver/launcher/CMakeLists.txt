set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)

add_library(SymSanLanucher SHARED launch.c)
target_include_directories(SymSanLanucher PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)
add_library(launcher_static STATIC launch.c)
install (TARGETS SymSanLanucher DESTINATION ${SYMSAN_LIB_DIR})
