set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
# fix pass bug: https://github.com/sampsyo/llvm-pass-skeleton/issues/7#issuecomment-401834287
set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-znodelete")
if(APPLE)
    # User teor2345 reports that this is required to make things work on MacOS X.
    set (CMAKE_MODULE_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-flat_namespace -Wl,-undefined,suppress")
endif(APPLE)

include(AddLLVM)

# Declare source files as optional to avoid LLVM CMake validation errors
set(LLVM_OPTIONAL_SOURCES
  TaintPass.cpp
  UCSanPass.cpp
)

add_llvm_pass_plugin(TaintPass TaintPass.cpp)
add_llvm_pass_plugin(UCSanPass UCSanPass.cpp)

install (TARGETS TaintPass UCSanPass DESTINATION ${SYMSAN_LIB_DIR})
