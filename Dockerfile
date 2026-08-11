FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

WORKDIR /work
COPY . /work/symsan

RUN apt-get update
RUN apt-get install -y cmake llvm-18 clang-18 libclang-18-dev libc++-18-dev libc++abi-18-dev libunwind-18-dev \
    python3-minimal python-is-python3 zlib1g-dev git joe libprotobuf-dev curl
RUN git clone --depth=1 --branch=v4.31c https://github.com/AFLplusplus/AFLplusplus /work/aflpp
RUN cd /work/aflpp && make PERFORMANCE=1 LLVM_CONFIG=llvm-config-18 NO_NYX=1 source-only -j4 && make install

RUN apt-get install -y libz3-dev libgoogle-perftools-dev libboost-container-dev python3-dev
RUN apt clean

RUN cd /work/symsan/ && mkdir -p build && \
    cd build && CC=clang-18 CXX=clang++-18 cmake -DCMAKE_INSTALL_PREFIX=. -DAFLPP_PATH=/work/aflpp ../  && \
    make -j4 && make install

## Rust/LibAFL bindings -- the recommended hybrid-fuzzing front end
## (bindings/rust, see bindings/rust/HYBRID_FUZZING.md).  LibAFL is pulled from
## the git rev pinned in Cargo.lock (`--locked`), so no separate checkout is
## needed; bindgen needs libclang (installed above).  SYMSAN_BUILD_DIR points
## the build at the install prefix produced just above (/work/symsan/build).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
ENV LIBCLANG_PATH=/usr/lib/llvm-18/lib
RUN cd /work/symsan/bindings/rust && \
    SYMSAN_BUILD_DIR=/work/symsan/build cargo build --release --locked

ENV KO_CC=clang-18
ENV KO_CXX=clang++-18
ENV KO_USE_FASTGEN=1
