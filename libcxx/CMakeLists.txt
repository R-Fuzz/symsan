# run rebuild.sh

install (FILES "build_taint/lib/libc++.a" DESTINATION "${SYMSAN_LIB_DIR}")
install (FILES "build_taint/lib/libc++abi.a" DESTINATION "${SYMSAN_LIB_DIR}")
install (FILES "build_taint/lib/libunwind.a" DESTINATION "${SYMSAN_LIB_DIR}")

