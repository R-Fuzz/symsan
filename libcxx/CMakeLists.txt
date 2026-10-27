# run rebuild.sh

install (FILES "build_taint/lib/libc++.a" DESTINATION "${SYMSAN_LIB_DIR}")
install (FILES "build_taint/lib/libc++abi.a" DESTINATION "${SYMSAN_LIB_DIR}")
install (FILES "build_taint/lib/libunwind.a" DESTINATION "${SYMSAN_LIB_DIR}")
# The copy linked under UCSan (rebuild.sh --ucsan), when built
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/build_ucsan/lib/libc++.a")
  install (FILES "build_ucsan/lib/libc++.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libc++-ucsan.a")
  install (FILES "build_ucsan/lib/libc++abi.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libc++abi-ucsan.a")
  install (FILES "build_ucsan/lib/libunwind.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libunwind-ucsan.a")
endif()
# UCSan's abilist for linking the instrumented libc++ (ucsan_opt --libcxx)
install (CODE "execute_process(COMMAND bash
  \"${CMAKE_CURRENT_SOURCE_DIR}/ucsan_abilist.sh\"
  \"${CMAKE_CURRENT_SOURCE_DIR}/build_taint/lib/libc++.a\"
  \"\${CMAKE_INSTALL_PREFIX}/${SYMSAN_LIB_DIR}/ucsan_libcxx_abilist.txt\"
  COMMAND_ERROR_IS_FATAL ANY)")

# Plain (uninstrumented) EH runtime for UCSan-only C++ targets — run
# rebuild_native.sh to produce these.  Installed with a -native suffix so they
# coexist with the taint-instrumented archives above.  See rebuild_native.sh
# for why UCSan needs a plain libc++abi/libunwind for exception handling.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/build_native/lib/libc++abi.a")
  install (FILES "build_native/lib/libc++abi.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libc++abi-native.a")
  install (FILES "build_native/lib/libunwind.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libunwind-native.a")
endif()

