#!/bin/bash
# libyaml: harness tests/run-parser-test-suite reading stdin (ConcoLLMic setup)
set -e; source /workspace/concollmic-eval/scripts/env.sh
S=$EVAL/src/libyaml; mkdir -p $S; cd $S
[ -d orig ] || git clone -q https://github.com/yaml/libyaml.git orig
git -C orig rev-parse HEAD > commit.txt
for r in ${ROLES:-symsan afl cmplog gcov}; do
  ( rm -rf $r; cp -r orig $r; cd $r; role_env $r
    bash ./bootstrap >/dev/null 2>&1
    [ $r = symsan ] && export KO_CONFIG=1
    ./configure --disable-shared > ../build-$r.log 2>&1
    unset KO_CONFIG
    make -j4 >> ../build-$r.log 2>&1 && echo "$r OK" || echo "$r FAIL" )
done
