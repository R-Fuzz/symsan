set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)

add_library(AFLGORT STATIC aflgo-rt.o.cpp)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
target_include_directories(AFLGORT PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(AFLGORT PRIVATE c++ c++abi)
install (TARGETS AFLGORT DESTINATION ${SYMSAN_LIB_DIR})
