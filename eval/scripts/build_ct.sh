#!/bin/bash
# build_ct.sh SUBJECT [ROLES="symsan afl cmplog gcov"] -- Cottontail (S&P'26) subjects, reconstructed harnesses
source /workspace/concollmic-eval/scripts/env.sh
SUB=$1; S=$EVAL/src/$SUB; D=$EVAL/cottontail/drivers; mkdir -p $S; cd $S
ROLES=${ROLES:-"symsan afl cmplog gcov"}
get() { [ -d orig ] && return; wget -q -O src.tgz "$1" && mkdir orig && tar xzf src.tgz -C orig --strip-components=1; }
case $SUB in
  libxml2) get https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.13.5/libxml2-v2.13.5.tar.gz;;
  libexpat) get https://github.com/libexpat/libexpat/archive/refs/tags/R_2_6_4.tar.gz;;
  sqlite) [ -d orig ] || { wget -q https://www.sqlite.org/2024/sqlite-amalgamation-3470000.zip && unzip -q sqlite-amalgamation-3470000.zip && mv sqlite-amalgamation-3470000 orig; };;
  unqlite) get https://github.com/symisc/unqlite/archive/refs/tags/v1.1.9.tar.gz;;
  mujs) get https://github.com/ccxvii/mujs/archive/refs/tags/1.3.5.tar.gz;;
  quickjs) get https://github.com/quickjs-ng/quickjs/archive/refs/tags/v0.7.0.tar.gz;;
  json-c) get https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz;;
  jansson) get https://github.com/akheron/jansson/archive/refs/tags/v2.14.tar.gz;;
esac
for r in $ROLES; do
 ( set -e; role_env $r
   if [ $r = gcov ]; then export CFLAGS="--coverage -g -O0 -fsanitize=address" CXXFLAGS="--coverage -g -O0 -fsanitize=address" LDFLAGS="--coverage -fsanitize=address"; fi
   # NB: ko-clang tests KO_DONT_OPTIMIZE for presence, not value, so =0 *keeps*
   # the -g -O0 above (no -O3) -- unlike the seven ConcoLLMic subjects, whose
   # symsan builds get ko-clang's -O3.  The 2026-11-03 baseline ran this way.
   [ $r = symsan ] && export KO_DONT_OPTIMIZE=0
   rm -rf $r; cp -r orig $r; cd $r; L=$S/build-$r.log; : > $L
   cmk() { mkdir -p build && cd build; if [ $r = symsan ]; then KO_CONFIG=1 cmake .. -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF "$@" >>$L 2>&1; else cmake .. -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF "$@" >>$L 2>&1; fi; make -j3 "${MK[@]}" >>$L 2>&1; cd ..; }
   case $SUB in
     libxml2) MK=(xmllint); cmk -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_ZLIB=OFF -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ICU=OFF -DLIBXML2_WITH_ICONV=ON -DLIBXML2_WITH_TESTS=OFF -DHAVE_LIBREADLINE=OFF -DHAVE_LIBHISTORY=OFF;;
     libexpat) cd expat; MK=(xmlwf); cmk -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_DOCS=OFF -DEXPAT_SHARED_LIBS=OFF; cd ..; mkdir -p build; ln -sf ../expat/build/xmlwf build/xmlwf;;
     sqlite) cp $D/sqlite_driver.c .; $CC $CFLAGS -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -c sqlite3.c -o sqlite3.o >>$L 2>&1; $CC $CFLAGS sqlite_driver.c sqlite3.o -o sqlite_driver $LDFLAGS -lm >>$L 2>&1;;
     unqlite) cp $D/unqlite_driver.c .; $CC $CFLAGS -c unqlite.c -o unqlite.o >>$L 2>&1; $CC $CFLAGS unqlite_driver.c unqlite.o -o unqlite_driver $LDFLAGS -lm >>$L 2>&1;;
     mujs) $CC $CFLAGS -std=c99 -o mujs main.c one.c $LDFLAGS -lm >>$L 2>&1;;
     quickjs) MK=(qjs_exe); cmk;;
     json-c) MK=(json_parse); cmk -DBUILD_APPS=ON -DDISABLE_WERROR=ON;;
     jansson) MK=(jansson); cmk -DJANSSON_BUILD_DOCS=OFF -DJANSSON_WITHOUT_TESTS=ON -DJANSSON_EXAMPLES=OFF; $CC $CFLAGS -Ibuild/include $D/jansson_driver.c build/lib/libjansson.a -o jansson_driver $LDFLAGS >>$L 2>&1;;
   esac ) && echo "[$SUB/$r] OK" || echo "[$SUB/$r] FAIL"
done
