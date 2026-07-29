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

if (DEFINED AFLPP_PATH)
    add_subdirectory(aflpp)
endif()

install (CODE "MESSAGE(STATUS \"Build & Install: libSymsanProxy.o\")")
install (CODE "execute_process(COMMAND \
    ${CMAKE_COMMAND} -E env KO_CC=${LLVM_TOOLS_BINARY_DIR}/clang \
    ${CMAKE_INSTALL_PREFIX}/${SYMSAN_BIN_DIR}/ko-clang \
    -c ${CMAKE_CURRENT_SOURCE_DIR}/harness-proxy.c \
    -o ${CMAKE_INSTALL_PREFIX}/${SYMSAN_LIB_DIR}/libSymsanProxy.o)")
