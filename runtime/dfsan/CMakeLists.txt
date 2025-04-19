# include_directories(..)

# Runtime library sources and build flags.
set(DFSAN_RTL_SOURCES
  dfsan.cpp
  dfsan_custom.cpp
  dfsan_interceptors.cpp
  taint_allocator.cpp
  union_util.cpp
  union_hashtable.cpp)

set(DFSAN_RTL_HEADERS
  dfsan.h
  dfsan_flags.inc
  dfsan_platform.h
  taint_allocator.h
  union_util.h
  union_hashtable.h)

set(DFSAN_COMMON_CFLAGS ${SANITIZER_COMMON_CFLAGS})

if(OS_NAME MATCHES "Linux" AND
   COMPILER_RT_LIBCXX_PATH AND
   COMPILER_RT_LIBCXXABI_PATH)
  list(APPEND DFSAN_COMMON_CFLAGS -nostdinc++ -D_LIBCPP_ABI_VERSION=Taint)
  # Remove -stdlib= which is unused when passing -nostdinc++.
  string(REGEX REPLACE "-stdlib=[a-zA-Z+]*" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
endif()

append_rtti_flag(OFF DFSAN_COMMON_CFLAGS)
# Prevent clang from generating libc calls.
append_list_if(COMPILER_RT_HAS_FFREESTANDING_FLAG -ffreestanding DFSAN_COMMON_CFLAGS)

# Static runtime library.
add_compiler_rt_component(dfsan)

foreach(arch ${DFSAN_SUPPORTED_ARCH})
  set(DFSAN_CFLAGS ${DFSAN_COMMON_CFLAGS})
  append_list_if(COMPILER_RT_HAS_FPIE_FLAG -fPIE DFSAN_CFLAGS)
  add_compiler_rt_runtime(dfsan_rt
    STATIC
    ARCHS ${arch}
    SOURCES ${DFSAN_RTL_SOURCES}
            $<TARGET_OBJECTS:RTInterception.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommonSymbolizer.${arch}>
    ADDITIONAL_HEADERS ${DFSAN_RTL_HEADERS}
    CFLAGS ${DFSAN_CFLAGS}
    PARENT_TARGET dfsan)
  add_sanitizer_rt_symbols(dfsan_rt
    ARCHS ${arch}
    EXTRA dfsan.syms.extra)
  add_dependencies(dfsan
    dfsan_rt-${arch}-symbols)

  if(OS_NAME MATCHES "Linux" AND
    COMPILER_RT_LIBCXX_PATH AND
    COMPILER_RT_LIBCXXABI_PATH)
    macro(partially_link_libcxx name dir arch)
      set(cxx_${arch}_merge_dir "${CMAKE_CURRENT_BINARY_DIR}/cxx_${arch}_merge.dir")
      file(MAKE_DIRECTORY ${cxx_${arch}_merge_dir})
      add_custom_command(TARGET dfsan_rt-${arch} POST_BUILD
        COMMAND ${CMAKE_LINKER} --whole-archive "$<TARGET_LINKER_FILE:dfsan_rt-${arch}>" --no-whole-archive ${dir}/lib/libc++.a --no-whole-archive ${dir}/lib/libc++abi.a -r -o ${name}.o
        COMMAND ${CMAKE_OBJCOPY} --localize-hidden ${name}.o
        COMMAND ${CMAKE_COMMAND} -E remove "$<TARGET_LINKER_FILE:dfsan_rt-${arch}>"
        COMMAND ${CMAKE_AR} qcs "$<TARGET_LINKER_FILE:dfsan_rt-${arch}>" ${name}.o
        WORKING_DIRECTORY ${cxx_${arch}_merge_dir}
      )
    endmacro()

    set(TARGET_CFLAGS ${TARGET_${arch}_CFLAGS} PARENT_SCOPE)
    set(LIBCXX_${arch}_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libcxx_taint_${arch})
    add_custom_libcxx(libcxx_taint_${arch} ${LIBCXX_${arch}_PREFIX}
      CFLAGS ${TARGET_CFLAGS}
             -D_LIBCPP_ABI_VERSION=Taint
             -D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS=1
             -fvisibility=hidden
      CMAKE_ARGS -DCMAKE_CXX_COMPILER_WORKS=ON
                -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                -DLIBCXX_ENABLE_EXCEPTIONS=ON
                -DLIBCXX_ABI_NAMESPACE=__Taint)
    target_compile_options(dfsan_rt-${arch} PRIVATE -isystem ${LIBCXX_${arch}_PREFIX}/include/c++/v1)
    add_dependencies(dfsan_rt-${arch} libcxx_taint_${arch}-build)
    partially_link_libcxx(taint ${LIBCXX_${arch}_PREFIX} ${arch})
  endif()

  install(FILES ${COMPILER_RT_OUTPUT_DIR}/libdfsan_rt-${arch}.a.syms
    DESTINATION ${COMPILER_RT_LIBRARY_INSTALL_DIR})
endforeach()

set(dfsan_abilist_dir ${COMPILER_RT_OUTPUT_DIR}/share)
set(dfsan_abilist_filename ${dfsan_abilist_dir}/dfsan_abilist.txt)
add_custom_target(dfsan_abilist ALL
  DEPENDS ${dfsan_abilist_filename})
add_custom_command(OUTPUT ${dfsan_abilist_filename}
                   VERBATIM
                   COMMAND
                    ${CMAKE_COMMAND} -E make_directory ${dfsan_abilist_dir}
                   COMMAND
                     cat ${CMAKE_CURRENT_SOURCE_DIR}/done_abilist.txt
                         ${CMAKE_CURRENT_SOURCE_DIR}/libc_ubuntu2204_abilist.txt
                         > ${dfsan_abilist_filename}
                   DEPENDS done_abilist.txt libc_ubuntu2204_abilist.txt)
add_dependencies(dfsan dfsan_abilist)
install(FILES ${dfsan_abilist_filename}
  DESTINATION ${COMPILER_RT_LIBRARY_INSTALL_DIR})
install(FILES "libc++_abilist.txt"
  DESTINATION ${COMPILER_RT_LIBRARY_INSTALL_DIR})

set(taint_linker_script_filename ${COMPILER_RT_OUTPUT_DIR}/taint.ld)
add_custom_target(taint_linker_script ALL
  DEPENDS ${taint_linker_script_filename})
add_custom_command(OUTPUT ${taint_linker_script_filename}
                   VERBATIM
                   COMMAND
                     cat ${CMAKE_CURRENT_SOURCE_DIR}/taint.ld
                         > ${taint_linker_script_filename}
                   DEPENDS taint.ld)
add_dependencies(dfsan taint_linker_script)
install(FILES ${taint_linker_script_filename}
  DESTINATION ${COMPILER_RT_LIBRARY_INSTALL_DIR})
