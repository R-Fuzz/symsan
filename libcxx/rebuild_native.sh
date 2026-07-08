#!/usr/bin/env bash
#
# Build a *plain* (uninstrumented) C++ exception-handling runtime —
# libc++abi + libunwind — for under-constrained (UCSan-only) binaries.
#
# Why a separate build:
#   UCSan replaces out-of-scope libc++ with "dangle" stubs that return
#   arbitrary symbolic values.  C++ exception handling cannot be modeled that
#   way: __cxa_throw is noreturn and must transfer control to a landing pad.
#   The EH passthrough in UCSanPass therefore re-points the dangle stubs at the
#   *plain* __cxa_* / __gxx_personality_v0 symbols, which must be resolved by a
#   real, concretely-running EH runtime.
#
#   The taint-instrumented libc++abi (built by rebuild.sh with ko-clang) renames
#   every instrumented function with a ".taint" suffix, so it exports
#   __cxa_throw.taint, not the plain __cxa_throw the passthrough calls.  This
#   script builds libc++abi + libunwind with plain clang-14, giving the plain EH
#   symbols.  Only the EH runtime is needed; libc++ (the STL) is left
#   out-of-scope and dangled by UCSan.
#
# usage: rebuild_native.sh
#   Override the compiler with KO_NATIVE_CC / KO_NATIVE_CXX (default clang-18).

# We are migrating to LLVM 18, so clang-18 is the default.
CC=${KO_NATIVE_CC:-clang-18}
CXX=${KO_NATIVE_CXX:-clang++-18}

# Derive the LLVM version to check out from the compiler itself so the EH
# runtime sources match the toolchain.
LLVM_VERSION=$(${CC} --version | sed -n 's/.*clang version \([0-9][0-9.]*\).*/\1/p' | head -1)
if [ -z "$LLVM_VERSION" ]; then
    echo "[-] Error: could not determine LLVM version from '${CC}'" 1>&2
    exit 1
fi
LLVM_MAJOR=${LLVM_VERSION%%.*}

NINJA_B=`which ninja 2>/dev/null`

if [ "$NINJA_B" = "" ]; then
    echo "[-] Error: can't find 'ninja' in your \$PATH. please install ninja-build" 1>&2
    echo "[-] Debian&Ubuntu: sudo apt-get install ninja-build" 1>&2
    exit 1
fi

set -euxo pipefail

CUR_DIR=`pwd`
# Keep a per-major-version source tree so multiple LLVM versions can coexist
# (shared with rebuild.sh).
LLVM_SRC="llvm_project-${LLVM_MAJOR}"

if [ ! -d $LLVM_SRC ]; then
  git clone --depth 1 --branch llvmorg-${LLVM_VERSION} https://github.com/llvm/llvm-project.git $LLVM_SRC
fi

# LLVM 16+ libunwind prefers glibc's _dl_find_object over dl_iterate_phdr to
# locate EH frames. _dl_find_object bypasses DFSan's dl_iterate_phdr wrapper and
# cannot resolve unwind info for symsan's fixed-address (taint.ld) binaries,
# which breaks C++ exception handling. Force the dl_iterate_phdr path.
# Idempotent: rewrites only the pristine guard line. (Shared source tree with
# rebuild.sh, so whichever runs first applies it and the other is a no-op.)
ASPACE="$LLVM_SRC/libunwind/src/AddressSpace.hpp"
if [ -f "$ASPACE" ]; then
  sed -i 's|^#if defined(DLFO_STRUCT_HAS_EH_DBASE) & defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)|#if 0 /* symsan: force dl_iterate_phdr; _dl_find_object bypasses DFSan */ \&\& defined(DLFO_STRUCT_HAS_EH_DBASE) \& defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)|' "$ASPACE"
fi

mkdir -p build_native
rm -rf build_native/*

# Plain clang-14 — no ko-clang, no taint/ucsan instrumentation, so the EH
# entry points keep their plain names (__cxa_throw, __gxx_personality_v0, ...).
cmake -G Ninja -S $LLVM_SRC/runtimes -B build_native \
    -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=${CC} -DCMAKE_CXX_COMPILER=${CXX} \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
    -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBUNWIND_ENABLE_SHARED=OFF \
    -DLIBCXX_CXX_ABI="libcxxabi" \
    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
    -DLLVM_DISTRIBUTION_COMPONENTS="cxxabi;unwind"

# Only build the EH runtime: libc++abi (the __cxa_*/personality layer) and
# libunwind (the unwinder).  libcxx is enabled only so libc++abi can find its
# headers at build time.
ninja -C build_native cxxabi unwind
