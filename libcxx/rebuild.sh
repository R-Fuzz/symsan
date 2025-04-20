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

LLVM_VERSION=14.0.6

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

mkdir -p build_taint
rm -rf build_taint/*

export KO_CONFIG=1
export KO_CC=clang-14
export KO_CXX=clang++-14
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

