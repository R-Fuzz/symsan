#!/bin/bash
# libyaml: harness tests/run-parser-test-suite reading stdin (ConcoLLMic setup)
set -e; source /workspace/concollmic-eval/scripts/env.sh
S=$EVAL/src/libyaml; mkdir -p $S; cd $S
# 90a56d4 is the HEAD the 2026-11-03 eval cloned (it recorded commit.txt, did not pin).
[ -d orig ] || { git clone -q https://github.com/yaml/libyaml.git orig && git -C orig checkout -q ${LIBYAML_REV:-90a56d4500aa1a1798514c5cb55c3ad4cb095f94}; }
git -C orig rev-parse HEAD > commit.txt
for r in ${ROLES:-symsan afl cmplog gcov}; do
  ( rm -rf $r; cp -r orig $r; cd $r; role_env $r
    bash ./bootstrap >/dev/null 2>&1
    [ $r = symsan ] && export KO_CONFIG=1
    ./configure --disable-shared > ../build-$r.log 2>&1
    unset KO_CONFIG
    make -j4 >> ../build-$r.log 2>&1 && echo "$r OK" || echo "$r FAIL" )
done
