#!/bin/bash
# Run unique-line replays from unique_jobs_*.txt (subject\tfuzzer\thost_queue_path).
set -euo pipefail
source /workspace/concollmic-eval/scripts/env.sh
JOBS=${1:-/workspace/concollmic-eval/runs/unique_jobs_small.txt}
OUT=/workspace/concollmic-eval/runs/unique_gcov
LOG=$OUT/batch.log
PAR=${UNIQUE_PAR:-3}
TO=${UNIQUE_TO:-5}
mkdir -p "$OUT"
: > "$LOG"
mapfile -t lines < <(grep -v '^#' "$JOBS" | grep -v '^$' || true)
echo "jobs=${#lines[@]} par=$PAR to=$TO" | tee -a "$LOG"

run_one() {
  local subj=$1 fk=$2 qhost=$3
  local q=${qhost/\/home\/csong\/symsan\/eval/\/workspace\/concollmic-eval}
  local info="$OUT/${subj}__${fk}.info"
  if [ -f "$info" ] && [ -s "$info" ]; then
    echo "SKIP $subj $fk" | tee -a "$LOG"
    return 0
  fi
  echo "$(date +%T) START $subj $fk" | tee -a "$LOG"
  if /workspace/concollmic-eval/scripts/unique_lines_replay.sh "$subj" "$q" "$info" "$TO" >>"$LOG" 2>&1; then
    echo "$(date +%T) DONE  $subj $fk" | tee -a "$LOG"
  else
    echo "$(date +%T) FAIL  $subj $fk" | tee -a "$LOG"
  fi
}

n=0
for line in "${lines[@]}"; do
  subj=$(printf '%s' "$line" | cut -f1)
  fk=$(printf '%s' "$line" | cut -f2)
  q=$(printf '%s' "$line" | cut -f3)
  run_one "$subj" "$fk" "$q" &
  n=$((n+1))
  if (( n % PAR == 0 )); then wait; fi
done
wait
echo "$(date +%T) ALL_DONE" | tee -a "$LOG"
python3 /workspace/concollmic-eval/scripts/unique_lines_analyze.py | tee "$OUT/summary.txt"
