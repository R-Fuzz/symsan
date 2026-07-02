#!/usr/bin/env bash
#
# usage: rebuild.sh path_to_ko_clang

if [[ $# -ne 1 ]]; then
    echo "Usage: ${0} path_to_ko_clang" 1>&2
    exit 1
fi

BIN_PATH=$(readlink -f "$0")
ROOT_DIR=$(dirname $(dirname $(dirname $BIN_PATH)))
CC=$(readlink -f "$1")
CXX=${CC}++

if [ ! -x $CC ]; then
    echo "[-] Error: cannot find the C compiler 'ko_clang'" 1>&2
    exit 1
fi

if [ ! -h $CXX ]; then
    echo "[-] Error: cannot find the CXX compiler 'ko_clang++'" 1>&2
    exit 1
fi

# The underlying (non-instrumented) clang that ko-clang wraps.  We are migrating
# to LLVM 18, so clang-18 is the default; override via the environment to build
# against a different LLVM (e.g. KO_CC=clang-14).
export KO_CC=${KO_CC:-clang-18}
export KO_CXX=${KO_CXX:-clang++-18}

# Derive the LLVM version to check out from the compiler itself so the libc++
# sources always match the toolchain doing the instrumentation.
LLVM_VERSION=$(${KO_CC} --version | sed -n 's/.*clang version \([0-9][0-9.]*\).*/\1/p' | head -1)
if [ -z "$LLVM_VERSION" ]; then
    echo "[-] Error: could not determine LLVM version from '${KO_CC}'" 1>&2
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
# Keep a per-major-version source tree so multiple LLVM versions can coexist.
LLVM_SRC="llvm_project-${LLVM_MAJOR}"

if [ ! -d $LLVM_SRC ]; then
  git clone --depth 1 --branch llvmorg-${LLVM_VERSION} https://github.com/llvm/llvm-project.git $LLVM_SRC
fi

# LLVM 16+ libunwind prefers glibc's _dl_find_object over dl_iterate_phdr to
# locate EH frames. _dl_find_object bypasses DFSan's dl_iterate_phdr wrapper and
# cannot resolve unwind info for symsan's fixed-address (taint.ld) binaries,
# which breaks C++ exception handling. Force the dl_iterate_phdr path.
# Idempotent: rewrites only the pristine guard line.
ASPACE="$LLVM_SRC/libunwind/src/AddressSpace.hpp"
if [ -f "$ASPACE" ]; then
  sed -i 's|^#if defined(DLFO_STRUCT_HAS_EH_DBASE) & defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)|#if 0 /* symsan: force dl_iterate_phdr; _dl_find_object bypasses DFSan */ \&\& defined(DLFO_STRUCT_HAS_EH_DBASE) \& defined(_LIBUNWIND_SUPPORT_DWARF_INDEX)|' "$ASPACE"
fi

mkdir -p build_taint
rm -rf build_taint/*

export KO_CONFIG=1
cmake -G Ninja -S $LLVM_SRC/runtimes -B build_taint \
    -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=${CC} -DCMAKE_CXX_COMPILER=${CXX} \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
    -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_CXX_ABI="libcxxabi" \
    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
    -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;unwind"

unset KO_CONFIG
ninja -C build_taint cxx cxxabi unwind

