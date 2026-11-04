#!/bin/bash
# Build the toolchain image (LLVM 18, AFL++ 4.31c, Rust). Once.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
exec docker build -t symsan-eval:latest -f "$HERE/Dockerfile" "$HERE"
