set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)

find_package(boost_container CONFIG)

if (NOT boost_container_FOUND)
    message(FATAL_ERROR "Failed to locate Boost")
endif()

## parser
add_library(rgd-parser STATIC rgd-parser.cpp)
target_include_directories(rgd-parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
    ${Boost_INCLUDE_DIRS}
)
target_compile_options(rgd-parser PRIVATE
    -O3 -g -mcx16 -march=native -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
)
target_link_libraries(rgd-parser PRIVATE
    Boost::container
)
