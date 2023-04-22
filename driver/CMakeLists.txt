set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)

## simple driver for testing out-of-process solving
add_executable(FGTest fgtest.cpp)
set_target_properties(FGTest PROPERTIES OUTPUT_NAME "fgtest")
target_include_directories(FGTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_options(FGTest PRIVATE "-lz3")
install (TARGETS FGTest DESTINATION ${SYMSAN_BIN_DIR})

add_subdirectory(aflpp)
