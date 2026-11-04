FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV LANG=C.UTF-8

# Toolchain for SymSan-main (LLVM 18) + AFL++ 4.31c + subject builds.
# Source trees are mounted at runtime; this image is the compilers and AFL++ only.
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
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
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
