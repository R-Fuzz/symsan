#!/bin/bash
# batch.sh JOBFILE OUTROOT DURATION ["CORES"] -- JOBFILE lines: "SUBJECT MODE"
# Round-robin assigns jobs to per-core queues; each core runs its queue sequentially (one job per core).
# Default cores: $EVAL_CORES (12 physical, no HT siblings; core 0 left free).
source /workspace/concollmic-eval/scripts/env.sh
JOBS=$1; OUTROOT=$(realpath -m $2); DUR=$3; read -a CORES <<< "${4:-$EVAL_CORES}"; mkdir -p $OUTROOT
n=${#CORES[@]}; i=0
declare -A Q
while read -r s m; do [ -z "$s" ] && continue; c=${CORES[$((i % n))]}; Q[$c]+="$s:$m "; i=$((i+1)); done < $JOBS
for c in "${CORES[@]}"; do
  ( for j in ${Q[$c]}; do s=${j%%:*}; m=${j##*:}; echo "$(date +%T) core$c start $s $m"
      $EVAL/scripts/run_one.sh $s $m $DUR $c $OUTROOT; echo "$(date +%T) core$c done $s $m"; done ) >> $OUTROOT/batch.log 2>&1 &
done
wait; echo "ALL DONE $(date)" >> $OUTROOT/batch.log
