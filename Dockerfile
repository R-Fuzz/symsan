FROM ubuntu:jammy

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

WORKDIR /work
COPY . /work/symsan

RUN apt-get update
RUN apt-get install -y cmake llvm-14 clang-14 libc++-14-dev libc++abi-14-dev python3-minimal python-is-python3 zlib1g-dev git joe libprotobuf-dev
RUN git clone https://github.com/AFLplusplus/AFLplusplus /workdir/aflpp
RUN cd /workdir/aflpp && git checkout v4.30c && make PERFORMANCE=1 LLVM_CONFIG=llvm-config-14 NO_NYX=1 source-only -j4 && make install

RUN apt-get install -y libz3-dev libgoogle-perftools-dev libboost-container-dev python3-dev
RUN apt clean

RUN cd /work/symsan/ && mkdir -p build && \
    cd build && CC=clang-14 CXX=clang++-14 cmake -DCMAKE_INSTALL_PREFIX=. -DAFLPP_PATH=/work/aflpp ../  && \
    make -j4 && make install

ENV KO_CC=clang-14
ENV KO_CXX=clang++-14
ENV KO_USE_FASTGEN=1
