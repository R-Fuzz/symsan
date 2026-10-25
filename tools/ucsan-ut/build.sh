#!/bin/bash
# Build the unit-test harness tools into OUTDIR.
#
#   tools/ucsan-ut/build.sh OUTDIR
#
# ut-unit links clang's libTooling, ut-entry only LLVM; both against
# LLVM_CONFIG's install (default llvm-config-18), with CXX (default clang++-18).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(realpath -m "$1")"
LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-18}"
CXX="${CXX:-clang++-18}"
mkdir -p "$OUT"
INC="$($LLVM_CONFIG --includedir)"
LIB="$($LLVM_CONFIG --libdir)"
VER="$($LLVM_CONFIG --version | cut -d. -f1)"
FLAGS=(-std=c++17 -O1 -fno-rtti -I"$INC")
"$CXX" "${FLAGS[@]}" "$HERE/ut_entry.cpp" -o "$OUT/ut-entry" -L"$LIB" -lLLVM-"$VER"
"$CXX" "${FLAGS[@]}" "$HERE/ut_unit.cpp" -o "$OUT/ut-unit" \
  "$LIB/libclang-cpp.so.$VER.1" -L"$LIB" -lLLVM-"$VER"
