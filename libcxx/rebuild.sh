#!/usr/bin/env bash
#
# usage: compile.sh path_to_ko_clang

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

LLVM_VERSION=12.0.1

NINJA_B=`which ninja 2>/dev/null`

if [ "$NINJA_B" = "" ]; then
    echo "[-] Error: can't find 'ninja' in your \$PATH. please install ninja-build" 1>&2
    echo "[-] Debian&Ubuntu: sudo apt-get install ninja-build" 1>&2
    exit 1
fi

set -euxo pipefail

CUR_DIR=`pwd`
LLVM_SRC="llvm_src"

if [ ! -d $LLVM_SRC ]; then
  wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/llvm-${LLVM_VERSION}.src.tar.xz
  wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/libcxx-${LLVM_VERSION}.src.tar.xz
  wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/libcxxabi-${LLVM_VERSION}.src.tar.xz
  wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/libunwind-${LLVM_VERSION}.src.tar.xz

  tar -Jxf ${CUR_DIR}/llvm-${LLVM_VERSION}.src.tar.xz
  mv llvm-${LLVM_VERSION}.src $LLVM_SRC
  tar -Jxf ${CUR_DIR}/libcxx-${LLVM_VERSION}.src.tar.xz
  mv libcxx-${LLVM_VERSION}.src libcxx
  tar -Jxf ${CUR_DIR}/libcxxabi-${LLVM_VERSION}.src.tar.xz
  mv libcxxabi-${LLVM_VERSION}.src libcxxabi
  tar -Jxf ${CUR_DIR}/libunwind-${LLVM_VERSION}.src.tar.xz
  mv libunwind-${LLVM_VERSION}.src libunwind
fi

mkdir -p build_taint
cd build_taint
rm -rf *

export KO_CONFIG=1
export KO_CC=clang-12
export KO_CXX=clang++-12
cmake -G Ninja -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=${CC} -DCMAKE_CXX_COMPILER=${CXX} \
    -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi;libunwind" \
    -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_CXX_ABI="libcxxabi" \
    -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
    -DLIBCXX_CXX_ABI_INCLUDE_PATHS=../libcxxabi/include \
    -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;unwind" \
    ../$LLVM_SRC

unset KO_CONFIG
ninja distribution

