add_executable(KOClang ko_clang.c)
set_target_properties(KOClang PROPERTIES OUTPUT_NAME "ko-clang")
# Let the driver version-gate the clang flags it forwards.
target_compile_definitions(KOClang PRIVATE
    LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR}
    LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR})

add_custom_command(TARGET KOClang POST_BUILD
    COMMAND ln -sf "ko-clang" "ko-clang++")
install (TARGETS KOClang DESTINATION ${SYMSAN_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/ko-clang++ DESTINATION ${SYMSAN_BIN_DIR})
install (PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/ucsan_opt DESTINATION ${SYMSAN_BIN_DIR})
