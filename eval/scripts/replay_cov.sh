#!/bin/bash
# replay_cov.sh SUBJECT RUN_DIR QUEUE_DIR [TIMEOUT=10]
# Replays seeds + QUEUE_DIR (sorted by mtime, like the artifact's run.sh) on a private
# copy of the gcov build with a per-input timeout, then writes gcovr summary
# (artifact coverage.sh format: l_per,l_abs,b_per,b_abs) to RUN_DIR/coverage_final.csv
# and a coarse time series (every 60s of mtime) to RUN_DIR/coverage_series.csv
source /workspace/concollmic-eval/scripts/env.sh; source $EVAL/scripts/subjects.sh
subj $1; RUN=$(realpath $2); Q=$(realpath $3); TO=${4:-10}
mkdir -p "$EVAL/runs"
exec 9>"$EVAL/runs/.replay.lock"
echo "$(date +%T) replay-lock wait $1"
flock 9
eval_wait_mem
echo "$(date +%T) replay-lock held $1 avail=$(eval_mem_avail_mb)MB"
G=$RUN/gcov-replay; rm -rf $G; cp -a $SRC/gcov $G; cd $G
find . -name '*.gcda' -delete; find . -name '*conftest*.gcno' -delete; find $SRC/gcov -name '*.gcda' -delete
# gcda paths are absolute (baked at compile time): redirect them into the private copy
export GCOV_PREFIX=$G GCOV_PREFIX_STRIP=$(echo $SRC/gcov | tr -cd / | wc -c)
CS=${COVSCRIPT:-$ART/$NAME/coverage.sh}; [ -f "$CS" ] || CS=$EVAL/scripts/coverage.sh
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
export GCOV_SRC_ROOT=$SRC/gcov
covsum() { (cd $G && bash $CS) ; }
mapfile -t seeds < <(find $SEEDS -maxdepth 1 -type f -printf '%T@ %p\n' | sort -n | cut -d' ' -f2-)
mapfile -t q < <(find $Q -maxdepth 1 -type f -not -name '.*' -printf '%T@ %p\n' | sort -n | cut -d' ' -f2-)
run1() { local f=$1 extra=()
  # oggenc writes input.ogg next to the input; seeds are on a ro mount.
  if [ "$NAME" = oggenc ]; then extra=(-Q -o "$RUN/._replay.ogg"); fi
  if [[ " $ARGS " == *" @@ "* ]]; then timeout -k 1 ${TO}s $G/$BIN "${extra[@]}" ${ARGS//@@/$f} >/dev/null 2>&1 </dev/null
  else timeout -k 1 ${TO}s $G/$BIN $ARGS < $f >/dev/null 2>&1; fi; }
echo "time,l_per,l_abs,b_per,b_abs,x" > $RUN/coverage_series.csv
if [ -f $RUN/start_time ]; then t0=$(cat $RUN/start_time); else t0=$(stat -c %Y ${q[0]:-${seeds[0]}}); fi; last=-999
for f in "${seeds[@]}"; do run1 $f; done
echo "0,$(covsum)" >> $RUN/coverage_series.csv
for f in "${q[@]}"; do run1 $f; t=$(( $(stat -c %Y $f) - t0 ))
  if (( t - last >= 60 )); then echo "$t,$(covsum)" >> $RUN/coverage_series.csv; last=$t; fi; done
echo "l_per,l_abs,b_per,b_abs,x" > $RUN/coverage_final.csv; covsum >> $RUN/coverage_final.csv
echo "$1 $(tail -1 $RUN/coverage_final.csv) inputs=${#q[@]}"
