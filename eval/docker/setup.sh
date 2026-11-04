#!/bin/bash
# Build SymSan, rust bindings, and/or subjects inside the eval container.
# Usage: setup.sh [symsan|rust|subjects|status|all]
set -euo pipefail
source /workspace/concollmic-eval/scripts/env.sh

CC_SUBS=(libyaml libmatheval bc confetti krep woff2 oggenc)
CT_SUBS=(libxml2 libexpat sqlite unqlite mujs quickjs json-c jansson)

log() { printf '[setup] %s\n' "$*"; }

build_symsan() {
  log "cmake + ninja install -> $SYMSAN"
  cmake -G Ninja -S /workspace/symsan-main -B /workspace/symsan-main/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/workspace/symsan-main/install \
    -DAFLPP_PATH="$AFLPP" \
    -DCMAKE_C_COMPILER=clang-18 \
    -DCMAKE_CXX_COMPILER=clang++-18 \
    -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm
  ninja -C /workspace/symsan-main/build install
  log "symsan installed: $(ls "$SYMSAN/bin/ko-clang")"
}

build_rust() {
  if [ ! -x "$SYMSAN/bin/ko-clang" ]; then
    log "ko-clang missing; building SymSan first"
    build_symsan
  fi
  log "cargo build --release --locked -> $SYMSAN_FUZZ"
  (
    cd /workspace/symsan-main/bindings/rust
    export PATH="$HOME/.cargo/bin:$PATH"
    export LIBCLANG_PATH=/usr/lib/llvm-18/lib
    export SYMSAN_BUILD_DIR="$SYMSAN"
    cargo build --release --locked
  )
  test -x "$SYMSAN_FUZZ"
  log "symsan-fuzz: $SYMSAN_FUZZ"
}

build_one_subject() {
  local s=$1
  case $s in
    libyaml)     "$EVAL/scripts/build_libyaml.sh" ;;
    libmatheval) "$EVAL/scripts/build_libmatheval.sh" ;;
    bc|confetti|krep|woff2|oggenc) "$EVAL/scripts/build_subject.sh" "$s" ;;
    libxml2|libexpat|sqlite|unqlite|mujs|quickjs|json-c|jansson)
      "$EVAL/scripts/build_ct.sh" "$s" ;;
    *) echo "unknown subject $s" >&2; return 1 ;;
  esac
}

build_subjects() {
  local list=("${CC_SUBS[@]}" "${CT_SUBS[@]}")
  if [ $# -gt 0 ]; then list=("$@"); fi
  local s
  for s in "${list[@]}"; do
    log "building $s"
    build_one_subject "$s" || log "WARN: $s failed"
  done
}

status() {
  echo "EVAL=$EVAL"
  echo "SYMSAN=$SYMSAN  ko-clang=$([ -x "$SYMSAN/bin/ko-clang" ] && echo yes || echo NO)"
  echo "AFLPP=$AFLPP  afl-fuzz=$([ -x "$AFLPP/afl-fuzz" ] && echo yes || echo NO)"
  echo "SYMSAN_FUZZ=$SYMSAN_FUZZ  ($([ -x "$SYMSAN_FUZZ" ] && echo yes || echo NO))"
  echo "ART=$ART  ($([ -d "$ART" ] && echo ok || echo MISSING))"
  local s
  for s in "${CC_SUBS[@]}" "${CT_SUBS[@]}"; do
    local ok=()
    for r in orig symsan afl cmplog gcov; do
      [ -e "$EVAL/src/$s/$r" ] && ok+=("$r")
    done
    printf '  %-12s %s\n' "$s" "${ok[*]:-missing}"
  done
}

# Fail unless every subject has its harness binary in each of $ROLES.  The
# build scripts log FAIL and carry on, so this is what stops an image build.
verify() {
  source "$EVAL/scripts/subjects.sh"
  local s r bad=0
  for s in "${CC_SUBS[@]}" "${CT_SUBS[@]}"; do
    subj "$s"
    for r in ${ROLES:-symsan afl cmplog gcov}; do
      if [ -x "$SRC/$r/$BIN" ]; then
        printf '  ok      %-12s %-7s %s\n' "$s" "$r" "$BIN"
      else
        printf '  MISSING %-12s %-7s %s\n' "$s" "$r" "$SRC/$r/$BIN"
        bad=1
      fi
    done
  done
  return $bad
}

cmd=${1:-all}
shift || true
case $cmd in
  symsan)    build_symsan ;;
  rust)      build_rust ;;
  subjects)  build_subjects "$@" ;;
  subject)   build_one_subject "${1:?subject name}" ;;
  status)    status ;;
  verify)    verify ;;
  all)       build_symsan; build_rust; build_subjects ;;
  *) echo "usage: $0 [symsan|rust|subjects [NAME...]|subject NAME|status|verify|all]" >&2; exit 1 ;;
esac
