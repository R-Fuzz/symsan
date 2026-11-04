#!/bin/bash
# summarize.sh RUNROOT -> table: run, final libafl/afl stats, coverage_final
for d in $1/*/; do d=${d%/}; n=$(basename $d); cov=$(tail -1 $d/coverage_final.csv 2>/dev/null)
  if [ -f $d/out/default/fuzzer_stats ]; then st=$(grep -E "^(execs_done|corpus_count|edges_found)" $d/out/default/fuzzer_stats | awk '{printf "%s=%s ",$1,$3}'); lib=$(ls $d/out/default/queue | grep -c "op:lib"); st="$st symsan_q=$lib"
  else st=$(tail -n1 $d/fuzz.log 2>/dev/null | grep -oE 'run time: [^,]+|executions: [0-9]+|corpus: [0-9]+|objectives: [0-9]+|finds_symsan: [0-9]+ corpus|shared_mem: [0-9]+' | tr '\n' ' '); fi
  gap=$(grep -oE "run time: [0-9m-]+s" $d/fuzz.log 2>/dev/null | uniq | python3 -c "
import sys,re
def s(x):
    m=re.match(r'run time: (?:(\d+)m-)?(\d+)s',x); return int(m.group(1) or 0)*60+int(m.group(2))
L=[s(l) for l in sys.stdin]; g=max([b-a for a,b in zip(L,L[1:])] or [0]); print(g)" 2>/dev/null)
  echo "$n | cov(l%,l,b%,b)=$cov | maxStatsGap=${gap}s | $st"; done
