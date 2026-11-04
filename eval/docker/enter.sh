#!/bin/bash
# Start (or exec into) the eval container with the handoff /workspace layout.
#   ./enter.sh              # interactive bash
#   ./enter.sh setup all    # run docker/setup.sh all (as root)
#   ./enter.sh <cmd...>     # any command
#
# Fuzz/campaign containers run as the invoking host uid:gid so eval/runs is
# writable/readable without chown. Override with SYMSAN_EVAL_USER=root.
set -euo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)          # /home/csong/symsan
EVAL=$(cd "$HERE/.." && pwd)             # /home/csong/symsan/eval
NAME=${SYMSAN_EVAL_NAME:-symsan-eval}
IMAGE=${SYMSAN_EVAL_IMAGE:-symsan-eval:latest}
HOST_UID=${HOST_UID:-$(id -u)}
HOST_GID=${HOST_GID:-$(id -g)}

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "image $IMAGE missing; build it with $HERE/build-image.sh" >&2
  exit 1
fi

mkdir -p "$EVAL/src" "$EVAL/runs" \
         "$EVAL/.cache/cargo-registry" "$EVAL/.cache/cargo-git" \
         "$EVAL/.cache/cargo-home" "$EVAL/.cache/home"

DOCKER_MOUNTS=(
  -v "$EVAL:/workspace/concollmic-eval"
  -v "$ROOT/symsan-main:/workspace/symsan-main"
  -v "$ROOT/vendor/ConcoLLMic-artifact:/workspace/ConcoLLMic-artifact:ro"
  -v "$EVAL/.cache/cargo-registry:/workspace/concollmic-eval/.cache/cargo-home/registry"
  -v "$EVAL/.cache/cargo-git:/workspace/concollmic-eval/.cache/cargo-home/git"
  -v "$HERE/run-as-host.sh:/usr/local/bin/run-as-host.sh:ro"
)
DOCKER_ENV=(
  -e EVAL=/workspace/concollmic-eval
  -e EVAL_CORES="${EVAL_CORES:-}"
  -e EVAL_MAX_FUZZ="${EVAL_MAX_FUZZ:-}"
  -e EVAL_MIN_AVAIL_MB="${EVAL_MIN_AVAIL_MB:-}"
  -e HOST_UID="$HOST_UID"
  -e HOST_GID="$HOST_GID"
  -e HOME=/workspace/concollmic-eval/.cache/home
  -e CARGO_HOME=/workspace/concollmic-eval/.cache/cargo-home
)

run() {
  local args=(
    --rm -i "${TTY[@]}"
    --name "$NAME"
    --shm-size="${SYMSAN_SHM_SIZE:-16g}"
    --ulimit core=1
    "${DOCKER_MOUNTS[@]}"
    -w /workspace
    "${DOCKER_ENV[@]}"
    "$IMAGE"
  )
  if [ "${SYMSAN_EVAL_USER:-}" = root ]; then
    docker run "${args[@]}" "$@"
  else
    docker run "${args[@]}" /usr/local/bin/run-as-host.sh "$@"
  fi
}

TTY=()
if [ -t 0 ] && [ -t 1 ]; then TTY=(-t); fi

if [ $# -eq 0 ]; then
  run bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec bash'
elif [ "$1" = setup ]; then
  shift
  docker run --rm -i "${TTY[@]}" \
    --name "$NAME" \
    --shm-size="${SYMSAN_SHM_SIZE:-16g}" \
    --ulimit core=1 \
    "${DOCKER_MOUNTS[@]}" \
    -w /workspace \
    -e EVAL=/workspace/concollmic-eval \
    "$IMAGE" \
    bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec /workspace/concollmic-eval/docker/setup.sh "$@"' _ "$@"
elif [ "$1" = campaign ] || [ "$1" = resume ]; then
  NAME=${SYMSAN_EVAL_CAMPAIGN_NAME:-symsan-eval-campaign}
  if docker inspect "$NAME" >/dev/null 2>&1; then
    echo "container $NAME already exists ($(docker inspect -f '{{.State.Status}}' "$NAME"))" >&2
    exit 1
  fi
  if [ "$1" = resume ]; then
    SCRIPT=/workspace/concollmic-eval/scripts/resume.sh
  else
    SCRIPT=/workspace/concollmic-eval/scripts/campaign.sh
  fi
  shift
  if [ "${SYMSAN_EVAL_USER:-}" = root ]; then
    docker run -d \
      --name "$NAME" \
      --shm-size="${SYMSAN_SHM_SIZE:-16g}" \
      --memory="${SYMSAN_EVAL_MEMORY:-48g}" \
      --ulimit core=1 \
      "${DOCKER_MOUNTS[@]}" \
      -w /workspace \
      "${DOCKER_ENV[@]}" \
      "$IMAGE" \
      bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec '"$SCRIPT"' "$@"' _ "$@"
  else
    docker run -d \
      --name "$NAME" \
      --shm-size="${SYMSAN_SHM_SIZE:-16g}" \
      --memory="${SYMSAN_EVAL_MEMORY:-48g}" \
      --ulimit core=1 \
      "${DOCKER_MOUNTS[@]}" \
      -w /workspace \
      "${DOCKER_ENV[@]}" \
      "$IMAGE" \
      /usr/local/bin/run-as-host.sh \
      bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec '"$SCRIPT"' "$@"' _ "$@"
  fi
else
  run bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec "$@"' _ "$@"
fi
