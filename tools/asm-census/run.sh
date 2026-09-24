#!/bin/bash
# Build the census plugin and run it over a list of bitcode files.
#
#   tools/asm-census/run.sh [--instrumented] <bclist> [outdir]
#
# <bclist> holds one bitcode path per line, relative to the list's own
# directory (e.g. ~/fast/linux/linux-6.8.2/bclist).  Entries that are not
# bitcode (native objects from .S files) are listed in <outdir>/skipped.txt.
# Writes <outdir>/all.jsonl and prints the summary.
#
# --instrumented runs UCSanPass and TaintPass over each file first (from
# SYMSAN_LIB, default the b4 install) and takes the census of what inline asm
# they leave.  Every function the file defines is put in scope, so every asm
# site is visited; a file the passes fail on (invalid IR) is listed in
# <outdir>/failed.txt.  Each file writes its own part, so the parallel runs
# never interleave their output.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTRUMENTED=0
if [ "${1:-}" = "--instrumented" ]; then
  INSTRUMENTED=1
  shift
fi
LIST="$(realpath "$1")"
OUT="$(realpath -m "${2:-asm-census.out}")"
LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-18}"
OPT="${OPT:-opt-18}"
NM="${NM:-llvm-nm-18}"
CXX="${CXX:-clang++-18}"
SYMSAN_LIB="${SYMSAN_LIB:-$HERE/../../b4/lib/symsan}"

mkdir -p "$OUT/parts" "$OUT/meta"
rm -f "$OUT"/parts/*.jsonl "$OUT/err.log" "$OUT/failed.txt" "$OUT/skipped.txt"

$CXX -shared -fPIC -O1 $($LLVM_CONFIG --cxxflags) \
  "$HERE/AsmCensus.cpp" -o "$OUT/AsmCensus.so"

census_one() {
  local f="$1" key part
  key="$(echo "$f" | tr / _)"
  part="$OUT/parts/$key.jsonl"
  if [ "$(head -c 2 "$f" 2>/dev/null)" != "BC" ]; then
    echo "$f" >> "$OUT/skipped.txt"
    return
  fi
  if [ "$INSTRUMENTED" = 0 ]; then
    "$OPT" -load-pass-plugin "$OUT/AsmCensus.so" -passes=asm-census \
      -disable-output "$f" > "$part" 2>>"$OUT/err.log" || true
    return
  fi
  # UCSanPass takes its scope from a METADATA file: all defined functions
  local fns meta="$OUT/meta/$key.yaml"
  fns="$("$NM" --defined-only "$f" 2>/dev/null |
         awk '($2=="T"||$2=="t") && $3!="" && $3 !~ /^\.L/ {print $3}')"
  [ -z "$fns" ] && return
  { echo "entry: $(echo "$fns" | head -1)"; echo "scope:"
    echo "$fns" | sed 's/^/  - /'; } > "$meta"
  if ! METADATA="$meta" "$OPT" \
        -load-pass-plugin "$SYMSAN_LIB/UCSanPass.so" \
        -load-pass-plugin "$SYMSAN_LIB/TaintPass.so" -passes=ucsan,taint \
        -ucsan-abilist="$SYMSAN_LIB/ucsan_abilist.txt" -ucsan-with-taint=true \
        -taint-abilist="$SYMSAN_LIB/dfsan_abilist.txt" -taint-with-ucsan=true \
        -o "$OUT/parts/$key.bc" "$f" 2>>"$OUT/err.log"; then
    echo "$f" >> "$OUT/failed.txt"
    return
  fi
  "$OPT" -load-pass-plugin "$OUT/AsmCensus.so" -passes=asm-census \
    -disable-output "$OUT/parts/$key.bc" > "$part" 2>>"$OUT/err.log" || true
  rm -f "$OUT/parts/$key.bc"
}
export -f census_one
export OPT NM OUT INSTRUMENTED SYMSAN_LIB

cd "$(dirname "$LIST")"
xargs -P "$(nproc)" -I{} bash -c 'census_one "$1"' _ {} < "$LIST"

cat "$OUT"/parts/*.jsonl > "$OUT/all.jsonl"
echo "skipped (not bitcode): $(cat "$OUT/skipped.txt" 2>/dev/null | wc -l)"
if [ "$INSTRUMENTED" = 1 ]; then
  echo "failed to instrument: $(cat "$OUT/failed.txt" 2>/dev/null | wc -l)"
fi
python3 "$HERE/agg.py" "$OUT/all.jsonl"
