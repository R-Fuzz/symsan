set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)

## launcher lib
add_subdirectory(launcher)

## shared session code (event pump, driver policy) used by the front-ends
add_subdirectory(session)

## simple driver for testing out-of-process solving
add_executable(FGTest fgtest.cpp)
set_target_properties(FGTest PROPERTIES OUTPUT_NAME "fgtest")
target_include_directories(FGTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(FGTest PRIVATE
  launcher
  z3parser
  ${Z3_LIBRARY}
  rt
)
install (TARGETS FGTest DESTINATION ${SYMSAN_BIN_DIR})

## standalone driver for testing the RGD (out-of-process) solver path
add_executable(AFLTest afltest.cpp)
set_target_properties(AFLTest PROPERTIES OUTPUT_NAME "afltest" CXX_STANDARD 17)
target_include_directories(AFLTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(AFLTest PRIVATE
  launcher
  symsan-session
  rgd-parser
  rgd-solver
  ${Z3_LIBRARY}
  rt
)
install (TARGETS AFLTest DESTINATION ${SYMSAN_BIN_DIR})

## the event channel's death paths -- traced child hangs, fork server killed,
## consumer stops reading -- which every other driver reaches only by accident.
## Launcher only: it never looks at what was traced, just at whether the call
## comes back.
add_executable(DeathTest deathtest.c)
set_target_properties(DeathTest PROPERTIES OUTPUT_NAME "deathtest")
target_link_libraries(DeathTest PRIVATE
  launcher
  rt
)
install (TARGETS DeathTest DESTINATION ${SYMSAN_BIN_DIR})

## truth-table oracle for the RGD parser's normalizer, all four stages at once
## (find_roots -> to_nnf -> to_dnf -> construct_task).  Synthesizes union tables
## in memory, so no launcher and no instrumented target.
add_executable(NormTest normtest.cpp)
set_target_properties(NormTest PROPERTIES OUTPUT_NAME "normtest" CXX_STANDARD 17)
target_include_directories(NormTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(NormTest PRIVATE
  rgd-parser
  rgd-solver
  ${Z3_LIBRARY}
  rt
)
install (TARGETS NormTest DESTINATION ${SYMSAN_BIN_DIR})

## offline check that the branch map joins SymSan branches to the *right* AFL++
## edges, against an afl-showmap run as ground truth
add_executable(CovCheck covcheck.cpp)
set_target_properties(CovCheck PROPERTIES OUTPUT_NAME "covcheck" CXX_STANDARD 17)
target_include_directories(CovCheck PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(CovCheck PRIVATE
  launcher
  symsan-session
  rgd-parser
  rgd-solver
  ${Z3_LIBRARY}
  rt
)
install (TARGETS CovCheck DESTINATION ${SYMSAN_BIN_DIR})

## standalone SMT-LIB2 front-end for the RGD jigsaw solver (bridges smtlib2 ->
## rgd::SearchTask directly, no target execution / launcher / parser needed)
add_executable(SMTTest smttest.cpp)
set_target_properties(SMTTest PROPERTIES OUTPUT_NAME "smttest" CXX_STANDARD 17)
target_include_directories(SMTTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(SMTTest PRIVATE
  rgd-solver
  ${Z3_LIBRARY}
  rt
)
install (TARGETS SMTTest DESTINATION ${SYMSAN_BIN_DIR})

## replay jigsaw's serialized constraint corpus (../jigsaw/tests/*_reload)
## through the RGD solver, to measure the JIT function-cache hit rate
add_executable(RGDReplay rgdreplay.cpp)
set_target_properties(RGDReplay PROPERTIES OUTPUT_NAME "rgdreplay" CXX_STANDARD 17)
target_include_directories(RGDReplay PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)
target_link_libraries(RGDReplay PRIVATE
  rgd-solver
  ${Z3_LIBRARY}
  rt
)
install (TARGETS RGDReplay DESTINATION ${SYMSAN_BIN_DIR})

if (DEFINED AFLPP_PATH)
    add_subdirectory(aflpp)
endif()

install (CODE "MESSAGE(STATUS \"Build & Install: libSymsanProxy.o\")")
install (CODE "execute_process(COMMAND \
    ${CMAKE_COMMAND} -E env KO_CC=${LLVM_TOOLS_BINARY_DIR}/clang \
    ${CMAKE_INSTALL_PREFIX}/${SYMSAN_BIN_DIR}/ko-clang \
    -c ${CMAKE_CURRENT_SOURCE_DIR}/harness-proxy.c \
    -o ${CMAKE_INSTALL_PREFIX}/${SYMSAN_LIB_DIR}/libSymsanProxy.o)")
