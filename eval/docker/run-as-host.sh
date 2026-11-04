#!/bin/bash
# Drop root -> host uid/gid after opening up the image toolchain under /root.
# Invoked as PID 1 with HOST_UID/HOST_GID set; remaining args are the user command.
set -euo pipefail
: "${HOST_UID:?}" "${HOST_GID:?}"
# /root is 700 in the base image; non-root cannot reach rustup otherwise.
chmod 755 /root
chmod -R a+rX /root/.cargo /root/.rustup 2>/dev/null || true
# Writable home + cargo caches on the bind mount (owned by host user).
export HOME=${HOME:-/workspace/concollmic-eval/.cache/home}
export CARGO_HOME=${CARGO_HOME:-/workspace/concollmic-eval/.cache/cargo-home}
mkdir -p "$HOME" "$CARGO_HOME/registry" "$CARGO_HOME/git"
# Prefer image rustc; keep venv on PATH.
export PATH="/root/.cargo/bin:/opt/venv/bin:${PATH}"
# Own cache dirs we just created if still root-owned from an older run.
chown -R "$HOST_UID:$HOST_GID" \
  /workspace/concollmic-eval/.cache/home \
  /workspace/concollmic-eval/.cache/cargo-home \
  /workspace/concollmic-eval/.cache/cargo-registry \
  /workspace/concollmic-eval/.cache/cargo-git \
  2>/dev/null || true
exec setpriv --reuid="$HOST_UID" --regid="$HOST_GID" --init-groups -- "$@"
