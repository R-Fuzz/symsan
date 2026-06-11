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
#   Override the compiler with KO_NATIVE_CC / KO_NATIVE_CXX (default clang-14).

LLVM_VERSION=14.0.6

CC=${KO_NATIVE_CC:-clang-14}
CXX=${KO_NATIVE_CXX:-clang++-14}

NINJA_B=`which ninja 2>/dev/null`

if [ "$NINJA_B" = "" ]; then
    echo "[-] Error: can't find 'ninja' in your \$PATH. please install ninja-build" 1>&2
    echo "[-] Debian&Ubuntu: sudo apt-get install ninja-build" 1>&2
    exit 1
fi

set -euxo pipefail

CUR_DIR=`pwd`
LLVM_SRC="llvm_project"

if [ ! -d $LLVM_SRC ]; then
  git clone --depth 1 --branch llvmorg-${LLVM_VERSION} https://github.com/llvm/llvm-project.git $LLVM_SRC
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
