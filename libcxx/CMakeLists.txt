# run rebuild.sh

install (FILES "build_taint/lib/libc++.a" DESTINATION "${SYMSAN_LIB_DIR}")
install (FILES "build_taint/lib/libc++abi.a" DESTINATION "${SYMSAN_LIB_DIR}")
install (FILES "build_taint/lib/libunwind.a" DESTINATION "${SYMSAN_LIB_DIR}")

# Plain (uninstrumented) EH runtime for UCSan-only C++ targets — run
# rebuild_native.sh to produce these.  Installed with a -native suffix so they
# coexist with the taint-instrumented archives above.  See rebuild_native.sh
# for why UCSan needs a plain libc++abi/libunwind for exception handling.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/build_native/lib/libc++abi.a")
  install (FILES "build_native/lib/libc++abi.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libc++abi-native.a")
  install (FILES "build_native/lib/libunwind.a" DESTINATION "${SYMSAN_LIB_DIR}" RENAME "libunwind-native.a")
endif()

