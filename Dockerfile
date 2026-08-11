FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

WORKDIR /work
COPY . /work/symsan

RUN apt-get update
RUN apt-get install -y cmake llvm-18 clang-18 libc++-18-dev libc++abi-18-dev libunwind-18-dev \
    python3-minimal python-is-python3 zlib1g-dev git joe libprotobuf-dev
RUN git clone --depth=1 --branch=v4.31c https://github.com/AFLplusplus/AFLplusplus /work/aflpp
RUN cd /work/aflpp && make PERFORMANCE=1 LLVM_CONFIG=llvm-config-18 NO_NYX=1 source-only -j4 && make install

RUN apt-get install -y libz3-dev libgoogle-perftools-dev libboost-container-dev python3-dev
RUN apt clean

RUN cd /work/symsan/ && mkdir -p build && \
    cd build && CC=clang-18 CXX=clang++-18 cmake -DCMAKE_INSTALL_PREFIX=. -DAFLPP_PATH=/work/aflpp ../  && \
    make -j4 && make install

ENV KO_CC=clang-18
ENV KO_CXX=clang++-18
ENV KO_USE_FASTGEN=1
