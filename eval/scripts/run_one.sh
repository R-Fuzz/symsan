#!/bin/bash
# run_one.sh SUBJECT MODE DURATION_SEC CORE OUTROOT [REPLAY_TIMEOUT=10]
# MODE (Z3 is never enabled in any mode):
#   libafl-i2s / libafl-jig   symsan-fuzz LibAFL hybrid, --symsan-no-jigsaw / default (i2s->jigsaw); --symsan-timeout $LIBAFL_TIMEOUT (200)
#   aflpp-i2s  / aflpp-jig    AFL++ 4.31c + libSymSanMutator.so hybrid; jig adds SYMSAN_USE_JIGSAW=1
#   cmo-i2s    / cmo-jig      same + AFL_CUSTOM_MUTATOR_ONLY=1 (pure concolic, coverage-guided queue)
#                             no havoc → AFL_DISABLE_TRIM (nothing grows the file back)
#   afl-cmplog                AFL++ 4.31c + CmpLog/RedQueen (-c $SRC/cmplog/$BIN -l 2AT) + havoc
#   afl-rq-only               same -c/-l 2AT + AFL_CUSTOM_MUTATOR_ONLY=1 (RedQueen, no havoc, no plugin)
#                             no havoc → AFL_DISABLE_TRIM
#   libafl-havoc / afl-plain  no concolic (fuzzing-only baselines);  libafl-dflt = symsan-fuzz defaults (timeout 60000)
source /workspace/concollmic-eval/scripts/env.sh; source $EVAL/scripts/subjects.sh
subj $1 || exit 1; MODE=$2; DUR=$3; CORE=$4; OUT=$5/$1-$MODE; RTO=${6:-10}
eval_acquire_slot
trap eval_release_slot EXIT
rm -rf $OUT; mkdir -p $OUT/seeds; cp $SEEDS/* $OUT/seeds/; cd $OUT
SYM=$SRC/symsan/$BIN; AFL=$SRC/afl/$BIN; CMP=$SRC/cmplog/$BIN
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1
date +%s > start_time; echo "$0 $*" > cmd.txt
# --foreground: signal only the fuzzer, not this script (else replay never runs).
T="timeout --foreground -k 10 $DUR taskset -c $CORE"
# Solver configs (Z3 never enabled):  *-i2s = input-to-state only;  *-jig = i2s -> JIGSAW
LT=${LIBAFL_TIMEOUT:-200}   # --symsan-timeout (ms); see README: default 60000 stalls on looping inputs
PLUG="AFL_CUSTOM_MUTATOR_LIBRARY=$SYMSAN/bin/libSymSanMutator.so SYMSAN_TARGET=$SYM SYMSAN_DONT_EXIT_ON_MEMERROR=1 SYMSAN_TOKENS=1"
case $MODE in
  libafl-i2s)   $T $SYMSAN_FUZZ -i seeds -o out --symsan-timeout $LT --symsan-no-jigsaw --symsan-tokens --symsan $SYM -- $AFL $ARGS > fuzz.log 2>&1; Q=out/queue;;
  libafl-jig)   $T $SYMSAN_FUZZ -i seeds -o out --symsan-timeout $LT --symsan-tokens --symsan $SYM -- $AFL $ARGS > fuzz.log 2>&1; Q=out/queue;;
  libafl-dflt)  $T $SYMSAN_FUZZ -i seeds -o out --symsan $SYM -- $AFL $ARGS > fuzz.log 2>&1; Q=out/queue;;
  libafl-havoc) $T $SYMSAN_FUZZ -i seeds -o out -- $AFL $ARGS > fuzz.log 2>&1; Q=out/queue;;
  aflpp-i2s)    env $PLUG $T $AFLPP/afl-fuzz -i seeds -o out -- $AFL $ARGS > fuzz.log 2>&1; Q=out/default/queue;;
  aflpp-jig)    env $PLUG SYMSAN_USE_JIGSAW=1 $T $AFLPP/afl-fuzz -i seeds -o out -- $AFL $ARGS > fuzz.log 2>&1; Q=out/default/queue;;
  # CMO/RQ-only can finish the queue in seconds then spin empty cycles; AFL_NO_UI
  # still prints every "Fuzzing test case" line → hundreds of GB of fuzz.log.
  cmo-i2s)      echo "log silenced (CMO empty-cycle spam)" > fuzz.log
                env $PLUG AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1 $T $AFLPP/afl-fuzz -i seeds -o out -- $AFL $ARGS >/dev/null 2>&1; Q=out/default/queue;;
  cmo-jig)      echo "log silenced (CMO empty-cycle spam)" > fuzz.log
                env $PLUG AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1 SYMSAN_USE_JIGSAW=1 $T $AFLPP/afl-fuzz -i seeds -o out -- $AFL $ARGS >/dev/null 2>&1; Q=out/default/queue;;
  afl-plain)    $T $AFLPP/afl-fuzz -i seeds -o out -- $AFL $ARGS > fuzz.log 2>&1; Q=out/default/queue;;
  afl-cmplog)   test -x "$CMP" || { echo "missing cmplog bin $CMP" >&2; exit 1; }
                $T $AFLPP/afl-fuzz -i seeds -o out -c $CMP -l 2AT -- $AFL $ARGS > fuzz.log 2>&1; Q=out/default/queue;;
  afl-rq-only)  test -x "$CMP" || { echo "missing cmplog bin $CMP" >&2; exit 1; }
                # no plugin: CUSTOM_MUTATOR_ONLY skips havoc/det; CmpLog stage still runs
                # RQ apply-at-site is same-length, so trim cannot grow back
                echo "log silenced (RQ-only empty-cycle spam)" > fuzz.log
                env AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1 \
                  $T $AFLPP/afl-fuzz -i seeds -o out -c $CMP -l 2AT -- $AFL $ARGS >/dev/null 2>&1; Q=out/default/queue;;
  *) echo bad mode; exit 1;;
esac
date +%s > end_time
# safety net: drop union tables of dead drivers (pre-patch launcher leaked them on SIGTERM/SIGKILL)
for f in /dev/shm/symsan-union-table-*; do [ -e "$f" ] || continue; p=${f##*-}; kill -0 $p 2>/dev/null || rm -f $f; done
mkdir -p $Q; $EVAL/scripts/replay_cov.sh $1 $OUT $Q $RTO > replay.log 2>&1
rm -rf $OUT/gcov-replay; tail -1 replay.log
