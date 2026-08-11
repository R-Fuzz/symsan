//! Bake the rpath to `libsymsan_c.so` into this crate's test binaries.
//!
//! Cargo propagates a dependency's `cargo:rustc-link-lib` and
//! `cargo:rustc-link-search` to everything downstream, but *not* its
//! `cargo:rustc-link-arg` -- so the rpath the `symsan` crate sets for itself
//! does not reach us, and its test binaries would fail to start with
//! "libsymsan_c.so: cannot open shared object file".
//!
//! `symsan` declares `links = "symsan_c"` and prints `cargo:lib_dir=...`, which
//! cargo hands to us as `DEP_SYMSAN_C_LIB_DIR`. Re-emitting it as a link arg
//! here covers this package's tests, benches and examples.

fn main() {
    let lib_dir = std::env::var("DEP_SYMSAN_C_LIB_DIR")
        .expect("the symsan crate's build script should have set DEP_SYMSAN_C_LIB_DIR");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    println!("cargo:rerun-if-changed=build.rs");
    // DEP_* only reaches *direct* dependents, so a binary crate built on this
    // one needs the same three lines and its own `symsan` path dependency; see
    // ../fuzzer/build.rs.
}
