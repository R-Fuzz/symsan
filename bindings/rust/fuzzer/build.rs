//! Bake the rpath to `libsymsan_c.so` into the fuzzer binary.
//!
//! See `../libafl-symsan/build.rs` for why this is needed in every package that
//! produces a runnable artifact: cargo does not propagate `rustc-link-arg`.

fn main() {
    let lib_dir = std::env::var("DEP_SYMSAN_C_LIB_DIR")
        .expect("the symsan crate's build script should have set DEP_SYMSAN_C_LIB_DIR");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    println!("cargo:rerun-if-changed=build.rs");
}
