#!/bin/bash
# Build the toolchain image (LLVM 18, AFL++ 4.31c, Rust). Once.
# It now also bakes in the ConcoLLMic artifact files, SymSan at one revision,
# symsan-fuzz, and all 15 subjects in their four roles (see Dockerfile).
#
#   build-image.sh [SYMSAN_REV] [-- DOCKER_BUILD_ARGS...]
#
# SYMSAN_REV (default eval-baseline-2026-11-03) is any revision of this
# repository -- a tag, a branch, HEAD.  It is exported with `git archive`, so
# uncommitted changes are NOT in the image.  The eval scripts themselves always
# come from this working tree's eval/.
#
# Env: SYMSAN_EVAL_IMAGE (default symsan-eval:latest); TMPDIR for the export.
# Example: build-image.sh HEAD -- --build-arg RUST_TOOLCHAIN=1.91.0
#
# Needs BuildKit (Docker >= 23) for the named `symsan` build context.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
EVAL=$(cd "$HERE/.." && pwd)
REPO=$(git -C "$EVAL" rev-parse --show-toplevel)

REV=eval-baseline-2026-11-03
if [ $# -gt 0 ] && [ "$1" != -- ]; then REV=$1; shift; fi
if [ "${1:-}" = -- ]; then shift; fi
IMAGE=${SYMSAN_EVAL_IMAGE:-symsan-eval:latest}

SHA=$(git -C "$REPO" rev-parse --verify "$REV^{commit}")
SRC=$(mktemp -d "${TMPDIR:-/tmp}/symsan-src.XXXXXX")
trap 'rm -rf "$SRC"' EXIT
git -C "$REPO" archive "$SHA" | tar -x -C "$SRC"
echo "SymSan $REV = $SHA -> $IMAGE"

docker build -t "$IMAGE" \
  -f "$HERE/Dockerfile" \
  --build-context symsan="$SRC" \
  --build-arg SYMSAN_REV="$SHA" \
  "$@" \
  "$EVAL"
