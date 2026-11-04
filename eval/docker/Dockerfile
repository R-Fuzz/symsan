# syntax=docker/dockerfile:1
#
# The hybrid-fuzzing eval image.  Build it with build-image.sh, not directly:
# the SymSan source comes in as the named build context `symsan` (a
# `git archive` of one revision), and the build context is eval/.
#
#   toolchain   LLVM 18, AFL++ 4.31c, Rust, gcovr, Z3      (no SymSan, no subjects)
#   eval        + the ConcoLLMic artifact files the eval reads
#               + 15 subjects x {afl, cmplog, gcov} builds  (SymSan-independent)
#               + SymSan, symsan-fuzz, and the subjects' symsan builds
#               + the runtime scripts
#
# A campaign needs nothing else from the host but a directory for runs/.

FROM ubuntu:24.04 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV LANG=C.UTF-8

# Toolchain for SymSan-main (LLVM 18) + AFL++ 4.31c + subject builds.
# Source trees are mounted at runtime; this image is the compilers and AFL++ only.
# (That is the `toolchain` stage; the `eval` stage below bakes the trees in.)
RUN apt-get update && apt-get install -y \
        ca-certificates curl wget git git-lfs unzip file \
        build-essential ninja-build cmake make pkg-config \
        autoconf automake libtool m4 \
        bison flex byacc texinfo ed \
        python3 python3-pip python3-venv python-is-python3 python3-dev \
        lcov \
        clang-18 llvm-18 llvm-18-dev libclang-18-dev libc++-18-dev libc++abi-18-dev \
        libunwind-18-dev \
        zlib1g-dev libz3-dev libgoogle-perftools-dev \
        libboost-container-dev libprotobuf-dev \
        guile-3.0-dev guile-3.0 \
        libreadline-dev \
        time procps psmisc \
        g++ gcc \
    && test -f "$(llvm-config-18 --includedir)/llvm/Support/raw_ostream.h" \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# AFL++ 4.31c (same rev the handoff used). Installed to /opt and /usr/local.
# Use a numeric -j: Dockerfile `$()` is env substitution, not a shell.
RUN git clone --depth=1 --branch=v4.31c https://github.com/AFLplusplus/AFLplusplus /opt/aflpp-4.31c \
    && make -C /opt/aflpp-4.31c PERFORMANCE=1 LLVM_CONFIG=llvm-config-18 \
           CC=clang-18 CXX=clang++-18 NO_NYX=1 source-only -j8 \
    && make -C /opt/aflpp-4.31c install

# Rust for bindings/rust (symsan-fuzz). rustup lives in /root/.cargo; enter.sh
# bind-mounts only registry/ and git/ so this toolchain stays visible.
# The 2026-11-03 baseline was built with whatever `stable` was then; crate
# versions are pinned by Cargo.lock (--locked), the compiler is not.
ARG RUST_TOOLCHAIN=stable
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain ${RUST_TOOLCHAIN}
ENV PATH="/root/.cargo/bin:${PATH}"
ENV LIBCLANG_PATH=/usr/lib/llvm-18/lib
ENV CARGO_HOME=/root/.cargo
ENV RUSTUP_HOME=/root/.rustup

# gcovr 8.3 matches Cottontail's collect_coverage.sh; lit for SymSan tests.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir 'gcovr==8.3' lit \
    && ln -s /opt/venv /opt/venv-gcovr8
ENV PATH="/opt/venv/bin:${PATH}"

# Ubuntu noble's libz3-dev is 4.8.12; CMake requires >= 4.8.15 (string theory
# APIs). Install 4.13.3 to /usr/local, which find_library prefers. The eval
# never turns Z3 on (--symsan-z3 / SYMSAN_USE_Z3 stay off).
RUN curl -fsSL -o /tmp/z3.zip \
      https://github.com/Z3Prover/z3/releases/download/z3-4.13.3/z3-4.13.3-x64-glibc-2.35.zip \
    && unzip -q /tmp/z3.zip -d /tmp \
    && cp /tmp/z3-4.13.3-x64-glibc-2.35/bin/libz3.so /usr/local/lib/ \
    && cp /tmp/z3-4.13.3-x64-glibc-2.35/include/*.h /usr/local/include/ \
    && ldconfig \
    && rm -rf /tmp/z3.zip /tmp/z3-4.13.3-x64-glibc-2.35

ENV KO_CC=clang-18
ENV KO_CXX=clang++-18
ENV KO_USE_FASTGEN=1
ENV AFLPP=/opt/aflpp-4.31c

WORKDIR /workspace
CMD ["/bin/bash"]

FROM toolchain AS eval

ENV EVAL=/workspace/concollmic-eval

# Seeds, coverage.sh, libmatheval's test.c and krep's patches for the seven
# ConcoLLMic subjects (scripts/subjects.sh, replay_cov.sh, build_*.sh).  Only
# those paths are checked out; the artifact's own instrumented tarballs and
# Dockerfiles are not used.  2fce97b is the artifact's HEAD as of 2026-09-08.
ARG CONCOLLMIC_ARTIFACT_REV=2fce97b878b6425919eddf0204952ebe29b4b0b9
RUN git clone -q --filter=blob:none --no-checkout \
        https://github.com/ConcoLLMic/ConcoLLMic-artifact /workspace/ConcoLLMic-artifact \
    && cd /workspace/ConcoLLMic-artifact \
    && git sparse-checkout set --no-cone \
        '/c_c++_programs/*/seeds/' '/c_c++_programs/*/coverage.sh' \
        '/c_c++_programs/libmatheval/test.c' '/c_c++_programs/krep/*.diff' \
    && git checkout -q "${CONCOLLMIC_ARTIFACT_REV}"

# What the subject builds read.  Copied apart from the run-time scripts so that
# editing those does not throw away the subject layers below.
COPY scripts/env.sh scripts/subjects.sh scripts/build_subject.sh scripts/build_ct.sh \
     scripts/build_libyaml.sh scripts/build_libmatheval.sh \
     /workspace/concollmic-eval/scripts/
COPY cottontail /workspace/concollmic-eval/cottontail
COPY docker/setup.sh /workspace/concollmic-eval/docker/setup.sh

# The three roles that do not involve SymSan, so a SymSan change does not
# rebuild them.  verify fails the build if any harness binary is missing (the
# build scripts themselves only log FAIL and go on).
RUN ROLES="afl cmplog gcov" $EVAL/docker/setup.sh subjects \
    && ROLES="afl cmplog gcov" $EVAL/docker/setup.sh verify

# SymSan at the revision build-image.sh exported, then symsan-fuzz, then the
# subjects' symsan role with this ko-clang.
COPY --from=symsan . /workspace/symsan-main
RUN $EVAL/docker/setup.sh symsan && $EVAL/docker/setup.sh rust
RUN ROLES=symsan $EVAL/docker/setup.sh subjects \
    && ROLES=symsan $EVAL/docker/setup.sh verify

# Run-time scripts and job lists.
COPY scripts /workspace/concollmic-eval/scripts
COPY jobs /workspace/concollmic-eval/jobs
COPY docker/run-as-host.sh /usr/local/bin/run-as-host.sh
# runs/ is the one bind mount; tmp/ and .cache/ must be writable by the host
# uid that run-as-host.sh drops to.
RUN mkdir -p $EVAL/runs $EVAL/tmp $EVAL/.cache \
    && chmod 1777 $EVAL/tmp $EVAL/.cache
ARG SYMSAN_REV=unknown
LABEL org.symsan.rev="${SYMSAN_REV}" \
      org.symsan.concollmic-artifact-rev="${CONCOLLMIC_ARTIFACT_REV}"
WORKDIR /workspace
