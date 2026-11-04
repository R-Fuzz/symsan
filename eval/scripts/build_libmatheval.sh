#!/bin/bash
# libmatheval 1.1.11 + artifact test.c (stdin)
set -e; source /workspace/concollmic-eval/scripts/env.sh
S=$EVAL/src/libmatheval; mkdir -p $S; cd $S
[ -f libmatheval-1.1.11.tar.gz ] || wget -q https://ftp.gnu.org/gnu/libmatheval/libmatheval-1.1.11.tar.gz
for r in ${ROLES:-symsan afl cmplog gcov}; do
  ( rm -rf $r; tar xzf libmatheval-1.1.11.tar.gz; mv libmatheval-1.1.11 $r; cd $r; role_env $r
    cp $ART/libmatheval/test.c .
    [ $r = symsan ] && export KO_CONFIG=1
    ./configure --disable-shared > ../build-$r.log 2>&1
    unset KO_CONFIG
    make -j4 -C lib >> ../build-$r.log 2>&1
    $CC $CFLAGS -g -o program ./test.c lib/.libs/libmatheval.a -lm $LDFLAGS >> ../build-$r.log 2>&1 && echo "$r OK" || echo "$r FAIL" )
done
