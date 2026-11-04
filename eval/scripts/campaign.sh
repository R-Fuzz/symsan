#!/bin/bash
# campaign.sh [REPEATS=5] [DURATION_SEC=3600] [JOBFILE] [OUTPREFIX]
# Sequential repeats of batch.sh. Each repeat writes to OUTPREFIX-rN.
# JOBFILE may be a bare name (cmo-i2s) for $EVAL/jobs/<name>.txt; OUTPREFIX
# then defaults to $EVAL/runs/<name>.
source /workspace/concollmic-eval/scripts/env.sh
REPEATS=${1:-5}
DUR=${2:-3600}
JOBS=${3:-$EVAL/jobs/tier1.txt}
if [[ "$JOBS" != */* ]]; then JOBS=$EVAL/jobs/${JOBS%.txt}.txt; fi
DEFAULT_PREFIX=$EVAL/runs/$(basename "$JOBS" .txt)
PREFIX=${4:-$DEFAULT_PREFIX}
# Parallel launch runs rq-only on cores 4-6; skip the queued copy on the
# nohavoc (cores 1-3) container only.
if [ -f "$EVAL/runs/.skip-rq-only" ] && [[ "$PREFIX" == *rq-only* ]] && \
   [[ "$EVAL_CORES" == "1 2 3" ]]; then
  echo "SKIP rq-only on cores [$EVAL_CORES] (running on 4-6) $(date -Is)"
  exit 0
fi
echo "CAMPAIGN start $(date -Is) repeats=$REPEATS dur=${DUR}s cores=[$EVAL_CORES] jobs=$JOBS"
for r in $(seq 1 "$REPEATS"); do
  echo "=== repeat $r/$REPEATS $(date -Is) -> $PREFIX-r$r ==="
  "$EVAL/scripts/batch.sh" "$JOBS" "$PREFIX-r$r" "$DUR"
  "$EVAL/scripts/summarize.sh" "$PREFIX-r$r" | tee "$PREFIX-r$r/summary.txt" || true
done
echo "CAMPAIGN ALL DONE $(date -Is)"
