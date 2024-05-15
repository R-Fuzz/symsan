set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)

find_package(Boost REQUIRED COMPONENTS container)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g")

## parser
add_library(rgd-parser STATIC rgd-parser.cpp)
target_include_directories(rgd-parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
    ${Boost_INCLUDE_DIRS}
)
target_link_libraries(rgd-parser PRIVATE
    Boost::container
)
