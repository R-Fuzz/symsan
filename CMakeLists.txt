cmake_minimum_required(VERSION 3.13)

project(symsan VERSION 1.2.2 LANGUAGES C CXX ASM)

find_package(LLVM REQUIRED CONFIG)

# Find Z3 (minimum version 4.8.15 required for string theory APIs)
# Prefer /usr/local over system
find_library(Z3_LIBRARY NAMES z3 PATHS /usr/local/lib NO_DEFAULT_PATH)
if (NOT Z3_LIBRARY)
    find_library(Z3_LIBRARY NAMES z3)
endif()
find_path(Z3_INCLUDE_DIR NAMES z3.h PATHS /usr/local/include NO_DEFAULT_PATH)
if (NOT Z3_INCLUDE_DIR)
    find_path(Z3_INCLUDE_DIR NAMES z3.h)
endif()

# Check Z3 version
if (Z3_INCLUDE_DIR)
    file(READ "${Z3_INCLUDE_DIR}/z3_version.h" Z3_VERSION_CONTENT)
    string(REGEX MATCH "#define Z3_MAJOR_VERSION[ \t]+([0-9]+)" _ "${Z3_VERSION_CONTENT}")
    set(Z3_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define Z3_MINOR_VERSION[ \t]+([0-9]+)" _ "${Z3_VERSION_CONTENT}")
    set(Z3_VERSION_MINOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define Z3_BUILD_NUMBER[ \t]+([0-9]+)" _ "${Z3_VERSION_CONTENT}")
    set(Z3_VERSION_PATCH ${CMAKE_MATCH_1})
    set(Z3_VERSION "${Z3_VERSION_MAJOR}.${Z3_VERSION_MINOR}.${Z3_VERSION_PATCH}")

    message(STATUS "Found Z3 version: ${Z3_VERSION}")

    # Require at least version 4.8.15
    if (Z3_VERSION_MAJOR LESS 4 OR
        (Z3_VERSION_MAJOR EQUAL 4 AND Z3_VERSION_MINOR LESS 8) OR
        (Z3_VERSION_MAJOR EQUAL 4 AND Z3_VERSION_MINOR EQUAL 8 AND Z3_VERSION_PATCH LESS 15))
        message(FATAL_ERROR "Z3 version ${Z3_VERSION} found, but version 4.8.15 or later is required (for string theory APIs)")
    endif()
endif()

message(STATUS "Z3_LIBRARY: ${Z3_LIBRARY}")
message(STATUS "Z3_INCLUDE_DIR: ${Z3_INCLUDE_DIR}")
message(STATUS "Z3_VERSION: ${Z3_VERSION}")

if (LLVM_FOUND)
    message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
    message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
    message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
    # SymSan requires LLVM >= 18 (the default on Ubuntu 24.04). Older versions
    # predate opaque pointers and the DFSan trampoline removal and are no longer
    # supported. (find_package(LLVM 18) can't be used: LLVM's version config
    # requires an exact major.minor match.)
    if (LLVM_VERSION_MAJOR LESS 18)
        message(FATAL_ERROR "SymSan requires LLVM >= 18, found ${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}")
    endif()
else()
    message(FATAL_ERROR "You haven't install LLVM !")
endif()

if (NOT TARGET LLVMPassConfig)
    add_library(LLVMPassConfig INTERFACE IMPORTED)
    set_target_properties(LLVMPassConfig PROPERTIES
        INTERFACE_COMPILE_OPTIONS "-fno-rtti" #-fpic
        INTERFACE_INCLUDE_DIRECTORIES "${LLVM_INCLUDE_DIRS}"
        INTERFACE_LINK_DIRECTORIES "${LLVM_LIBRARY_DIRS}"
        INTERFACE_COMPILE_DEFINITIONS "LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR};LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR};"
        # INTERFACE_LINK_OPTIONS "-Wl,-znodelete"
    )
endif()

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

include_directories(include)

set(SYMSAN_BIN_DIR "bin")
set(SYMSAN_LIB_DIR "lib/symsan")

add_subdirectory(compiler)
add_subdirectory(instrumentation)
add_subdirectory(runtime)
add_subdirectory(wrappers)
add_subdirectory(parsers)
add_subdirectory(solvers)
add_subdirectory(backend)
add_subdirectory(driver)
add_subdirectory(tests)
add_subdirectory(libcxx)
add_subdirectory(bindings/python)
