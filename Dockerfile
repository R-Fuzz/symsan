FROM ubuntu:focal

WORKDIR /workdir
COPY . /workdir/symsan
RUN apt-get update
RUN apt-get install -y cmake llvm-12 clang-12 libc++-12-dev libc++abi-12-dev python
RUN cd symsan/ && mkdir -p build && cd build && CC=clang-12 CXX=clang++-12 cmake -DCMAKE_INSTALL_PREFIX=. ../ && make -j && make install


