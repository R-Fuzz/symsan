set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)

find_package(Python3 COMPONENTS Interpreter Development)

if (Python3_Development_FOUND)
  message(STATUS "Python3_VERSION ${Python3_VERSION}")
else()
  message(FATAL_ERROR "Cannot find Python development!")
endif()

add_library(pysymsan SHARED symsan-py.cpp)
set_target_properties(pysymsan PROPERTIES PREFIX "")
set_target_properties(pysymsan PROPERTIES OUTPUT_NAME "symsan")
set_target_properties(pysymsan PROPERTIES SUFFIX ".cpython-${Python3_VERSION_MAJOR}${Python3_VERSION_MINOR}-x86_64-linux-gnu.so")
target_include_directories(pysymsan PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
  ${Python3_INCLUDE_DIRS}
)
target_link_libraries(pysymsan PRIVATE
  launcher
  z3parser
  z3
  ${Python3_LIBRARIES}
  rt
)
install (TARGETS Fastgen DESTINATION ${SYMSAN_LIB_DIR})
