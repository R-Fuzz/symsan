#!/bin/bash
# Start (or exec into) the eval container with the handoff /workspace layout.
#   ./enter.sh                                     # interactive bash
#   ./enter.sh campaign REPEATS DUR JOBS [PREFIX]  # detached campaign.sh
#   ./enter.sh <cmd...>                            # any command
#
# SymSan, symsan-fuzz, AFL++, the 15 subjects and the scripts are all in the
# image (build-image.sh); setup no longer happens here.  The one bind mount is
# the host's runs directory, $SYMSAN_EVAL_RUNS (default ~/symsan-eval/runs),
# at /workspace/concollmic-eval/runs.
#
# Fuzz/campaign containers run as the invoking host uid:gid so eval/runs is
# writable/readable without chown. Override with SYMSAN_EVAL_USER=root.
set -euo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
NAME=${SYMSAN_EVAL_NAME:-symsan-eval}
IMAGE=${SYMSAN_EVAL_IMAGE:-symsan-eval:latest}
RUNS=${SYMSAN_EVAL_RUNS:-$HOME/symsan-eval/runs}
HOST_UID=${HOST_UID:-$(id -u)}
HOST_GID=${HOST_GID:-$(id -g)}

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "image $IMAGE missing; build it with $HERE/build-image.sh" >&2
  exit 1
fi

mkdir -p "$RUNS"

DOCKER_ARGS=(
  --shm-size="${SYMSAN_SHM_SIZE:-16g}"
  --ulimit core=1
  -v "$RUNS:/workspace/concollmic-eval/runs"
  -w /workspace
  -e HOST_UID="$HOST_UID"
  -e HOST_GID="$HOST_GID"
  -e HOME=/workspace/concollmic-eval/.cache/home
)
# Pass the pinning knobs only when set: env.sh fills in defaults with
# ${VAR:-...}, which an empty `-e VAR=` would also trigger, but being explicit
# keeps `docker inspect` honest about what a campaign ran with.
for v in EVAL_CORES EVAL_MAX_FUZZ EVAL_MIN_AVAIL_MB EVAL_SLOTS_DIR LIBAFL_TIMEOUT; do
  if [ -n "${!v:-}" ]; then DOCKER_ARGS+=(-e "$v=${!v}"); fi
done

# Drop to the host uid unless SYMSAN_EVAL_USER=root.
WRAP=()
[ "${SYMSAN_EVAL_USER:-}" = root ] || WRAP=(/usr/local/bin/run-as-host.sh)

TTY=()
if [ -t 0 ] && [ -t 1 ]; then TTY=(-t); fi

if [ $# -eq 0 ]; then
  exec docker run --rm -i "${TTY[@]}" --name "$NAME" "${DOCKER_ARGS[@]}" "$IMAGE" \
    "${WRAP[@]}" bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec bash'
elif [ "$1" = campaign ]; then
  shift
  NAME=${SYMSAN_EVAL_CAMPAIGN_NAME:-symsan-eval-campaign}
  if docker inspect "$NAME" >/dev/null 2>&1; then
    echo "container $NAME already exists ($(docker inspect -f '{{.State.Status}}' "$NAME"))" >&2
    exit 1
  fi
  docker run -d --name "$NAME" \
    --memory="${SYMSAN_EVAL_MEMORY:-48g}" \
    "${DOCKER_ARGS[@]}" "$IMAGE" \
    "${WRAP[@]}" bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec /workspace/concollmic-eval/scripts/campaign.sh "$@"' _ "$@"
  echo "started $NAME -- follow with: docker logs -f --tail 50 $NAME"
else
  exec docker run --rm -i "${TTY[@]}" --name "$NAME" "${DOCKER_ARGS[@]}" "$IMAGE" \
    "${WRAP[@]}" bash -lc 'source /workspace/concollmic-eval/scripts/env.sh && exec "$@"' _ "$@"
fi
