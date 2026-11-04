#!/bin/bash
# build_subject.sh SUBJECT  [ROLES="symsan afl cmplog gcov"]
# Mirrors the ConcoLLMic artifact's <subject>/symsan.Dockerfile build steps, but with
# SymSan-main ko-clang (LLVM 18), AFL++ 4.31c, and gcc --coverage, one tree per role.
source /workspace/concollmic-eval/scripts/env.sh
SUB=$1; S=$EVAL/src/$SUB; mkdir -p $S; cd $S
ROLES=${ROLES:-"symsan afl cmplog gcov"}
log() { echo "[$SUB/$r] $*"; }
fetch() {
 case $SUB in
  bc) [ -d orig ] || { wget -q https://ftp.gnu.org/gnu/bc/bc-1.08.1.tar.gz && tar xzf bc-1.08.1.tar.gz && mv bc-1.08.1 orig; };;
  confetti) [ -d orig ] || { wget -q https://github.com/hgs3/confetti/releases/download/v1.0.0-beta.4/confetti-1.0.0-beta.4.tar.gz && tar xzf confetti-1.0.0-beta.4.tar.gz && mv confetti-1.0.0-beta.4 orig; };;
  krep) [ -d orig ] || { git clone -q https://github.com/davidesantangelo/krep.git orig && cd orig && git checkout -q 9c4d41c && patch -p1 < $ART/krep/Makefile.diff && patch -p1 < $ART/krep/krep.diff; cd ..; };;
  woff2) [ -d orig ] || { git clone -q --recursive https://github.com/google/woff2.git orig && cd orig && git reset -q --hard 0f4d304faa1c62994536dc73510305c7357da8d4 && (cd brotli && git reset -q --hard 533843e3546cd24c8344eaa899c6b0b681c8d222); cd ..; };;
  oggenc) [ -d orig ] || { git clone -q https://github.com/xiph/vorbis-tools.git orig && git -C orig reset -q --hard 235540c05ad3f9cdc673ca09c237c9a9b5bda6eb; }
          [ -d ogg-src ] || git clone -q https://gitlab.xiph.org/xiph/ogg.git ogg-src
          [ -d vorbis-src ] || git clone -q https://gitlab.xiph.org/xiph/vorbis.git vorbis-src
          git -C ogg-src rev-parse HEAD > ogg.commit; git -C vorbis-src rev-parse HEAD > vorbis.commit;;
 esac
}
fetch
for r in $ROLES; do
 ( set -e; role_env $r; rm -rf $r; cp -r orig $r; cd $r; L=$S/build-$r.log; : > $L
   CFG() { if [ $r = symsan ]; then KO_CONFIG=1 ./configure "$@" >>$L 2>&1; else ./configure "$@" >>$L 2>&1; fi; }
   case $SUB in
    bc) CFG; if [ $r = gcov ]; then make AM_CFLAGS="-fprofile-arcs -ftest-coverage" >>$L 2>&1; else make >>$L 2>&1; fi;;
    confetti) autoreconf -fvi >>$L 2>&1; CFG --disable-shared; make >>$L 2>&1;;
    krep) if [ $r = gcov ]; then make CC=gcc BASE_CFLAGS="-fprofile-arcs -ftest-coverage" BASE_LDFLAGS="-fprofile-arcs -ftest-coverage" >>$L 2>&1; else make >>$L 2>&1; fi;;
    woff2) make clean >>$L 2>&1 || true; if [ $r = gcov ]; then make all CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" LFLAGS="$LDFLAGS" LDFLAGS="$LDFLAGS" >>$L 2>&1; else make -j4 all >>$L 2>&1; fi;;
    oggenc)
      # Per-role libogg/libvorbis (artifact installed them into /usr/local).
      # gcov also builds them here so we do not depend on distro -dev packages.
      P=$S/deps-$r; rm -rf $P $S/ogg-$r $S/vorbis-$r
      cp -r $S/ogg-src $S/ogg-$r; cp -r $S/vorbis-src $S/vorbis-$r
      # Artifact used distro libogg/libvorbis (no coverage). For the gcov
      # role, keep deps uninstrumented so .gcda stay under src/oggenc/gcov
      # (lcov only scans the copied vorbis-tools tree).
      if [ $r = gcov ]; then
        (cd $S/ogg-$r && ./autogen.sh >>$L 2>&1 && \
          CFLAGS="-g -O2" CXXFLAGS="-g -O2" LDFLAGS="" CFG --disable-shared --prefix=$P && \
          CFLAGS="-g -O2" CXXFLAGS="-g -O2" LDFLAGS="" make >>$L 2>&1 && make install >>$L 2>&1)
      else
        (cd $S/ogg-$r && ./autogen.sh >>$L 2>&1 && CFG --disable-shared --prefix=$P && make >>$L 2>&1 && make install >>$L 2>&1)
      fi
      # TaintPass + vorbis's -O3/-ffast-math leaves vector IR in psy.c that
      # LLVM 18 ISel cannot lower in the .taint clone (Cannot select bitcast).
      if [ $r = symsan ]; then
        (cd $S/vorbis-$r && ./autogen.sh >>$L 2>&1 && \
          KO_DONT_OPTIMIZE=1 CFLAGS="-g -O0" CXXFLAGS="-g -O0" \
          PKG_CONFIG_PATH=$P/lib/pkgconfig CFG --disable-shared --prefix=$P && \
          KO_DONT_OPTIMIZE=1 CFLAGS="-g -O0" CXXFLAGS="-g -O0" make >>$L 2>&1 && \
          make install >>$L 2>&1)
      elif [ $r = gcov ]; then
        (cd $S/vorbis-$r && ./autogen.sh >>$L 2>&1 && \
          CFLAGS="-g -O2" CXXFLAGS="-g -O2" LDFLAGS="" \
          PKG_CONFIG_PATH=$P/lib/pkgconfig CFG --disable-shared --prefix=$P && \
          CFLAGS="-g -O2" CXXFLAGS="-g -O2" LDFLAGS="" make >>$L 2>&1 && \
          make install >>$L 2>&1)
      else
        (cd $S/vorbis-$r && ./autogen.sh >>$L 2>&1 && \
          PKG_CONFIG_PATH=$P/lib/pkgconfig CFG --disable-shared --prefix=$P && \
          make >>$L 2>&1 && make install >>$L 2>&1)
      fi
      test -f "$P/lib/libvorbis.a"
      export PKG_CONFIG_PATH=$P/lib/pkgconfig
      ./autogen.sh >>$L 2>&1
      # po/*.gmo needs gettext msgfmt; we only need the oggenc binary.
      CFG --disable-shared --disable-nls
      make -C share >>$L 2>&1
      make -C oggenc >>$L 2>&1
      test -x oggenc/oggenc;;
   esac ) && log OK || log FAIL
done
