FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

WORKDIR /workdir
COPY . /workdir/symsan

RUN apt-get update
RUN apt-get install -y cmake llvm-12 clang-12 libc++-12-dev libc++abi-12-dev python zlib1g-dev git joe libprotobuf-dev
RUN git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus /workdir/aflpp
ENV LLVM_CONFIG=llvm-config-12
RUN cd /workdir/aflpp && CC=clang-12 CXX=clang++-12 make install

RUN apt-get install -y python3-minimal python-is-python3 libz3-dev libgoogle-perftools-dev libprotobuf-dev protobuf-compiler
RUN apt clean

RUN cd symsan/ && mkdir -p build && \
    cd build && CC=clang-12 CXX=clang++-12 cmake -DCMAKE_INSTALL_PREFIX=. -DAFLPP_PATH=/workdir/aflpp ../  && \
    make -j4 && make install
