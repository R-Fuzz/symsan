## Optional cargo build of the Rust bindings, enabled with -DSYMSAN_BUILD_RUST=ON.
##
## This does not try to teach cmake about the Rust dependency graph -- it just
## shells out to cargo, which already tracks it. The one thing cmake has to
## supply is SYMSAN_BUILD_DIR, so build.rs links against *this* build rather
## than whichever of b2/b3/b4 it would otherwise find first.

find_program(CARGO_EXECUTABLE cargo)
if (NOT CARGO_EXECUTABLE)
    message(FATAL_ERROR
        "SYMSAN_BUILD_RUST=ON but cargo was not found. "
        "Install a Rust toolchain (https://rustup.rs) or configure with -DSYMSAN_BUILD_RUST=OFF.")
endif()

set(SYMSAN_RUST_PROFILE "release" CACHE STRING
    "Cargo profile for the Rust bindings: debug or release")
if (SYMSAN_RUST_PROFILE STREQUAL "release")
    set(_cargo_profile_flag --release)
else()
    set(_cargo_profile_flag "")
endif()

## Not ALL: the C++ build must stay usable without a Rust toolchain even when
## someone has flipped the option on in a stale cache. Build it with
## `make symsan-rust`.
add_custom_target(symsan-rust
    COMMAND ${CMAKE_COMMAND} -E env
        "SYMSAN_BUILD_DIR=${CMAKE_INSTALL_PREFIX}"
        ${CARGO_EXECUTABLE} build ${_cargo_profile_flag}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building the Rust bindings (cargo, ${SYMSAN_RUST_PROFILE})"
    USES_TERMINAL
    VERBATIM)

## cargo links against libsymsan_c.so from the *install* prefix, so the install
## has to have happened first. Depending on the target alone is not enough --
## hence the note rather than an add_dependencies() that would not help.
add_custom_target(symsan-rust-test
    COMMAND ${CMAKE_COMMAND} -E env
        "SYMSAN_BUILD_DIR=${CMAKE_INSTALL_PREFIX}"
        ${CARGO_EXECUTABLE} test ${_cargo_profile_flag}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Testing the Rust bindings (run `make install` first)"
    USES_TERMINAL
    VERBATIM)

message(STATUS "Rust bindings enabled: `make symsan-rust` (profile: ${SYMSAN_RUST_PROFILE})")
