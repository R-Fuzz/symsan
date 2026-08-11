## shared session code for symsan front-ends
##
## symsan-session bundles the parts every front-end needs -- the event pump
## (trace-session.cpp) and, later, the RGD driver policy -- so that the AFL++
## mutator, the LibAFL stage and the Python binding do not each carry a copy.
##
## It also provides the single definition of __dfsan::get_label_info, which the
## RGD solvers reference (solvers/i2s-solver.cpp).  Anything that links both
## symsan-session and rgd-solver must therefore NOT define it itself.

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)

add_library(symsan-session STATIC
  trace-session.cpp
  concolic-session.cpp
  branch-map.cpp
)
target_include_directories(symsan-session PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
)
target_link_libraries(symsan-session PUBLIC
  launcher
  rgd-parser
  rgd-solver
)

## libsymsan_c -- the C ABI (include/symsan_c.h) over the above.
##
## This is what non-C++ front-ends bind against; bindings/rust/symsan runs
## bindgen over the header and links this.  It has to be a shared library so
## that cargo can link it without knowing how to reconstruct symsan's transitive
## C++ dependency list; ldd shows z3, LLVM-18, tcmalloc, boost_container and
## profiler are all shared already, so nothing here forces a static link.
add_library(symsan_c SHARED symsan_c.cpp)
target_include_directories(symsan_c PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
)
target_link_libraries(symsan_c PRIVATE
  symsan-session
  ${Z3_LIBRARY}
  rt
)
## The launcher primitives in launch.h are half of the L1 surface, but a static
## archive only contributes the members someone references -- symsan_set_*
## setters that this file happens not to call would be dropped, and an FFI user
## would get an undefined symbol at load time.  Force the whole archive in.
target_link_options(symsan_c PRIVATE
  "LINKER:--whole-archive,$<TARGET_FILE:launcher>,--no-whole-archive"
)
add_dependencies(symsan_c launcher)

install (TARGETS symsan_c DESTINATION ${SYMSAN_LIB_DIR})
install (FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/symsan_c.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/launch.h
  DESTINATION include/symsan
)
