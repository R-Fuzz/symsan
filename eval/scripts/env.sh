# Common environment for all eval scripts.
# Inside the eval container these paths match the GrokBot handoff layout.
export EVAL=${EVAL:-/workspace/concollmic-eval}
export ART=${ART:-/workspace/ConcoLLMic-artifact/c_c++_programs}
export SYMSAN=${SYMSAN:-/workspace/symsan-main/install}
export AFLPP=${AFLPP:-/opt/aflpp-4.31c}
export SYMSAN_FUZZ=${SYMSAN_FUZZ:-/workspace/symsan-main/bindings/rust/target/release/symsan-fuzz}
export KO_CC=${KO_CC:-clang-18} KO_CXX=${KO_CXX:-clang++-18} KO_USE_FASTGEN=${KO_USE_FASTGEN:-1}
# 16 physical cores are 0-15; HT siblings are 16-31. Use 12 physical cores
# and leave 0 free (same convention as the GrokBot handoff).
export EVAL_CORES="${EVAL_CORES:-1 2 3 4 5 6 7 8 9 10 11 12}"
# Host RAM is shared (strata-host often holds tens of GB). Cap concurrent
# fuzz+replay jobs and refuse to start when MemAvailable is below this.
export EVAL_MAX_FUZZ="${EVAL_MAX_FUZZ:-6}"
export EVAL_MIN_AVAIL_MB="${EVAL_MIN_AVAIL_MB:-8192}"
# Parallel campaigns on disjoint cores need separate slot dirs, else they
# serialize on the shared 1..MAX_FUZZ namespace.
export EVAL_SLOTS_DIR="${EVAL_SLOTS_DIR:-$EVAL/runs/.slots}"
eval_mem_avail_mb() { awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo; }
eval_wait_mem() {
  local min=${EVAL_MIN_AVAIL_MB:-8192} a
  while true; do
    a=$(eval_mem_avail_mb)
    [ "$a" -ge "$min" ] && return 0
    echo "$(date +%T) mem-wait ${a}MB < ${min}MB"
    sleep 20
  done
}
eval_acquire_slot() {
  local dir="${EVAL_SLOTS_DIR:-$EVAL/runs/.slots}"
  mkdir -p "$dir"
  local i p
  while true; do
    eval_wait_mem
    for i in $(seq 1 "${EVAL_MAX_FUZZ:-6}"); do
      if mkdir "$dir/$i" 2>/dev/null; then
        echo $$ >"$dir/$i/pid"
        EVAL_SLOT=$i
        EVAL_SLOT_DIR=$dir
        echo "$(date +%T) slot $i/${EVAL_MAX_FUZZ:-6} dir=$dir avail=$(eval_mem_avail_mb)MB"
        return 0
      fi
      p=$(cat "$dir/$i/pid" 2>/dev/null || true)
      if [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; then
        rm -rf "$dir/$i"
      fi
    done
    echo "$(date +%T) slot-wait max=${EVAL_MAX_FUZZ:-6} dir=$dir avail=$(eval_mem_avail_mb)MB"
    sleep 15
  done
}
eval_release_slot() {
  local dir="${EVAL_SLOT_DIR:-${EVAL_SLOTS_DIR:-$EVAL/runs/.slots}}"
  [ -n "${EVAL_SLOT:-}" ] && rm -rf "$dir/$EVAL_SLOT"
  EVAL_SLOT=
}
# venv (gcovr 8.3, lit) and rustup, if present
case ":$PATH:" in *":/opt/venv/bin:"*) ;; *) export PATH=/opt/venv/bin:${PATH};; esac
case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) export PATH=$HOME/.cargo/bin:${PATH};; esac
# compatibility with coverage_ct.sh's original venv-gcovr8 path
if [ ! -e "$EVAL/venv-gcovr8" ] && [ -x /opt/venv/bin/gcovr ]; then
  ln -sfn /opt/venv "$EVAL/venv-gcovr8" 2>/dev/null || true
fi
# roles: symsan afl cmplog gcov
role_env() {
  case "$1" in
    symsan) export CC=$SYMSAN/bin/ko-clang CXX=$SYMSAN/bin/ko-clang++ CFLAGS="-g" CXXFLAGS="-g";;
    afl)    export CC=$AFLPP/afl-clang-fast CXX=$AFLPP/afl-clang-fast++ CFLAGS="-g -O2" CXXFLAGS="-g -O2"; unset AFL_LLVM_CMPLOG AFL_CMPLOG;;  # NB: AFL_LLVM_CMPLOG=0 still ENABLES cmplog in afl-cc 4.31c
    cmplog) export CC=$AFLPP/afl-clang-fast CXX=$AFLPP/afl-clang-fast++ CFLAGS="-g -O2" CXXFLAGS="-g -O2" AFL_LLVM_CMPLOG=1;;
    gcov)   export CC=gcc CXX=g++ CFLAGS="-fprofile-arcs -ftest-coverage" CXXFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage";;
  esac
}
