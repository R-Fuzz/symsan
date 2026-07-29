//! Build script for the `symsan` crate.
//!
//! Two jobs:
//!   1. run bindgen over `include/symsan_c.h`, so the `unsafe` declarations in
//!      `sys` are generated from the real header rather than transcribed by
//!      hand (transcribed ones drift, and a drifted FFI signature is a
//!      segfault, not a compile error);
//!   2. tell rustc where `libsymsan_c.so` is and bake an rpath, so the test
//!      binaries and the example fuzzer run without `LD_LIBRARY_PATH`.
//!
//! The library itself is *not* built here.  It comes out of the CMake build,
//! which needs LLVM 18, Z3 and a compiler-rt bootstrap; reimplementing that in
//! a build script would be a second thing to keep in sync. Run
//! `cd b4 && make -j && make install` first.

use std::env;
use std::path::{Path, PathBuf};

/// Locate the symsan install prefix -- the directory holding `lib/symsan/`.
///
/// `SYMSAN_BUILD_DIR` wins if set.  Otherwise we look for the conventional
/// build directories next to the repository root, newest layout first.  (Per
/// CLAUDE.md the current one is `b4`; `b3`/`b2` are older LLVM versions kept
/// around, so try `b4` first and fall back rather than guessing wrong.)
fn find_symsan_build(repo_root: &Path) -> Option<PathBuf> {
    if let Ok(dir) = env::var("SYMSAN_BUILD_DIR") {
        let p = PathBuf::from(dir);
        // Accept either the prefix itself or something one level up from it,
        // since "build dir" and "install prefix" are the same path in-tree.
        if p.join("lib/symsan").is_dir() {
            return Some(p);
        }
        // Set but wrong: fail loudly instead of silently searching elsewhere,
        // otherwise you link one build and debug another.
        panic!(
            "SYMSAN_BUILD_DIR={} does not contain lib/symsan; \
             did you run `make install`?",
            p.display()
        );
    }

    for candidate in ["b4", "b3", "b2", "build"] {
        let p = repo_root.join(candidate);
        if p.join("lib/symsan").is_dir() {
            return Some(p);
        }
    }
    None
}

fn main() {
    // bindings/rust/symsan -> bindings/rust -> bindings -> <repo root>
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .ancestors()
        .nth(3)
        .expect("crate is not three levels below the repository root")
        .to_path_buf();

    let include_dir = repo_root.join("include");
    let header = include_dir.join("symsan_c.h");
    assert!(
        header.is_file(),
        "cannot find {}; expected this crate to live at \
         <symsan>/bindings/rust/symsan",
        header.display()
    );

    let build_dir = find_symsan_build(&repo_root).unwrap_or_else(|| {
        panic!(
            "cannot find a symsan build under {}. Build it first \
             (`cd b4 && make -j && make install`), or point SYMSAN_BUILD_DIR \
             at the install prefix.",
            repo_root.display()
        )
    });
    let lib_dir = build_dir.join("lib/symsan");

    // --- link ---------------------------------------------------------------
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=symsan_c");
    // Without an rpath every consumer would need LD_LIBRARY_PATH, including
    // `cargo test`, which is a poor first experience.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    // Downstream crates (libafl-symsan, fuzzer) read these via DEP_SYMSAN_*.
    println!("cargo:lib_dir={}", lib_dir.display());
    println!("cargo:build_dir={}", build_dir.display());
    // ...and *this* crate's own code reads them via env!(), which is how the
    // integration tests find ko-clang to build their target with.  `rustc-env`
    // is compile-time only; it does not leak into the runtime environment.
    println!("cargo:rustc-env=SYMSAN_BUILD_DIR_RESOLVED={}", build_dir.display());
    println!("cargo:rustc-env=SYMSAN_REPO_ROOT={}", repo_root.display());

    // --- generate the bindings ---------------------------------------------
    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", include_dir.display()))
        // Only wrap our own surface.  Without this we would also pull in every
        // type reachable from <sys/types.h> via launch.h.
        .allowlist_function("symsan_.*")
        .allowlist_type("symsan_.*")
        .allowlist_var("SYMSAN_.*")
        // Map the C enums onto plain integer constants rather than Rust enums:
        // a Rust enum with a value outside its variants is instant UB, and
        // these cross an FFI boundary where we cannot prove the value is in
        // range.  The safe wrapper converts explicitly.
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        // Carry the doc comments from symsan_c.h into rustdoc.
        .clang_arg("-fparse-all-comments")
        .generate_comments(true)
        // Rebuild when the headers change.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed on include/symsan_c.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    println!("cargo:rerun-if-env-changed=SYMSAN_BUILD_DIR");
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", include_dir.join("launch.h").display());
}
