#!/bin/bash
# Build the census plugin and run it over a list of bitcode files.
#
#   tools/asm-census/run.sh <bclist> [outdir]
#
# <bclist> holds one bitcode path per line, relative to the list's own
# directory (e.g. ~/fast/linux/linux-6.8.2/bclist).  Entries that are not
# bitcode (native objects from .S files) are skipped by opt with an error in
# <outdir>/err.log.  Writes <outdir>/all.jsonl and prints the summary.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LIST="$(realpath "$1")"
OUT="$(realpath -m "${2:-asm-census.out}")"
LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-18}"
OPT="${OPT:-opt-18}"
CXX="${CXX:-clang++-18}"

mkdir -p "$OUT/parts"
rm -f "$OUT"/parts/*.jsonl "$OUT/err.log"

$CXX -shared -fPIC -O1 $($LLVM_CONFIG --cxxflags) \
  "$HERE/AsmCensus.cpp" -o "$OUT/AsmCensus.so"

cd "$(dirname "$LIST")"
export OPT OUT
xargs -P "$(nproc)" -I{} sh -c \
  '"$OPT" -load-pass-plugin "$OUT/AsmCensus.so" -passes=asm-census \
     -disable-output "$1" > "$OUT/parts/$(echo "$1" | tr / _).jsonl" \
     2>>"$OUT/err.log" || true' _ {} < "$LIST"

cat "$OUT"/parts/*.jsonl > "$OUT/all.jsonl"
echo "skipped (not bitcode): $(grep -ac '^opt' "$OUT/err.log" || true)"
python3 "$HERE/agg.py" "$OUT/all.jsonl"
