#!/bin/bash
# unique_lines_replay.sh SUBJECT QUEUE_DIR OUT_INFO [TIMEOUT=5]
# Replay QUEUE_DIR (+ seeds) onto a private gcov copy; dump lcov .info (line hits).
# Uses the same lcov path as eval/scripts/coverage.sh so numbers match campaign.
set -euo pipefail
source /workspace/concollmic-eval/scripts/env.sh
source "$EVAL/scripts/subjects.sh"
subj "$1"
Q=$(realpath "$2")
OUT_INFO=$(realpath -m "$3")
TO=${4:-5}
mkdir -p "$(dirname "$OUT_INFO")"
G=$(mktemp -d "$EVAL/tmp/unique-gcov-XXXXXX")
cleanup() { rm -rf "$G"; }
trap cleanup EXIT
cp -a "$SRC/gcov"/. "$G"/
find "$G" -name '*.gcda' -delete
find "$G" -name '*conftest*.gcno' -delete
export GCOV_PREFIX=$G
export GCOV_PREFIX_STRIP
GCOV_PREFIX_STRIP=$(echo "$SRC/gcov" | tr -cd / | wc -c)
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

run1() {
  local f=$1 extra=()
  if [ "$NAME" = oggenc ]; then extra=(-Q -o "$G/._replay.ogg"); fi
  if [[ " $ARGS " == *" @@ "* ]]; then
    timeout -k 1 ${TO}s "$G/$BIN" "${extra[@]}" ${ARGS//@@/$f} >/dev/null 2>&1 </dev/null || true
  else
    timeout -k 1 ${TO}s "$G/$BIN" $ARGS <"$f" >/dev/null 2>&1 || true
  fi
}

n=0
while IFS= read -r f; do run1 "$f"; n=$((n+1)); done < <(
  find "$SEEDS" -maxdepth 1 -type f 2>/dev/null
  find "$Q" -maxdepth 1 -type f ! -name '.*'
)
(cd "$G" && lcov --capture --directory . --output-file "$OUT_INFO" \
  --rc branch_coverage=1 --ignore-errors mismatch,source,gcov >/dev/null 2>&1) \
  || (cd "$G" && lcov --capture --directory . --output-file "$OUT_INFO" \
       --rc lcov_branch_coverage=1 >/dev/null 2>&1)
# quick sanity: line count
labs=$(lcov --summary "$OUT_INFO" --rc branch_coverage=1 2>&1 | awk '/lines/{gsub(/[()]/,"",$3); print $3; exit}')
echo "$1 queue=$Q inputs=$n l_abs=${labs:-?} info=$OUT_INFO"
