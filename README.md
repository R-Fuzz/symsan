[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# SymSan: Time and Space Efficient Concolic Execution via Dynamic Data-Flow Analysis

SymSan (Symbolic Sanitizer) is an efficient concolic execution engine based on the
Data-Floow Sanitizer (DFSan) framework. By modeling forward symbolic execution as
a dynamic data-flow analysis and leveraging the time and space efficient data-flow
tracking infrastructure from DFSan, SymSan imposes much lower runtime overhead
than previous symbolic execution engines.

Similar to other compilation-based symbolic executor like [SymCC](https://github.com/eurecom-s3/symcc),
SymSan uses compile-time `instrumentation` to insert symbolic execution logic into
the target program, and a `runtime` supporting library to maintain symbolic states
during execution.

To learn more, checkout our [paper](https://www.usenix.org/conference/usenixsecurity22/presentation/chen-ju) at USENIX Security 2022.

## Building

Because SymSan leverages the shadow memory implementation from LLVM's sanitizers,
it has more strict dependency on the LLVM version. Right now only LLVM 12 is
tested.

### Build Requirements

- Linux-amd64 (Tested on Ubuntu 20.04)
- [LLVM 12.0.1](http://llvm.org/docs/index.html): clang, libc++, libc++abi

### Compilation

Create a `build` directory and execute the following commands in it:

```shell
$ CC=clang-12 CXX=clang-12 cmake -DCMAKE_INSTALL_PREFIX=/path/to/install -DCMAKE_BUILD_TYPE=Release /path/to/symsan/source
$ make
$ make install
```

### Build in Docker

```
docker build -t symsan .
docker run  --rm --ulimit core=0 symsan bash -c 'cd /workdir/symsan && ./check.sh 2>/dev/null'
```

### LIBCXX

The repo contains instrumented libc++ and libc++abi to support C++ programs.
To rebuild these libraries from source, execute the `rebuild.sh` script in the
`libcxx` directory.

## Test

To verify the code works, try the a simple test (forked from [Angora](https://github.com/AngoraFuzzer/Angora)):

```
cd tests/mini
KO_CC=clang-12 KO_USE_Z3=1 /path/to/ko-clang mini.c -o mini.taint
python -c "print('A'*20)" > i
TAINT_OPTIONS="taint_file=i" ./mini.taint i
./mini.taint id-0-0-0
```

### Environment Options

* `KO_CC` specifies the clang to invoke, if the default version isn't clang-12,
  set this variable to allow the compiler wrapper to find the correct clang.

* `KO_CXX` specifies the clang++ to invoke, if the default version isn't clang++-12,
  set this variable to allow the compiler wrapper to find the correct clang++.

* `KO_USE_Z3` enables the in-process Z3-based solver. By default, it is disabled,
  so SymSan will only perform symbolic constraint collection without solving.
  SymSan also supports out-of-process solving, which provides better compatiblility.
  Check [FastGen](https://github.com/R-Fuzz/fastgen).

* `KO_USE_NATIVE_LIBCXX` enables using the native uninstrumented libc++ and libc++abi.

* `KO_DONT_OPTIMIZE` don't override the optimization level to `O3`.

### Hybrid Fuzzing

SymSan needs a driver to perform hybrid fuzzing, like [FastGen](https://github.com/R-Fuzz/fastgen).
It could also be used as a custom mutator for [AFL++](https://github.com/AFLplusplus/AFLplusplus).

## Documentation

Still under construction, unfortunately.

## Reference

To cite SymSan in scientific work, please use the following BibTeX:

``` bibtex
@inproceedings {chen2020symsan,
  author =       {Ju Chen and Wookhyun Han and Mingjun Yin and Haochen Zeng and
                  Chengyu Song and Byoungyong Lee and Heng Yin and Insik Shin},
  title =        {SymSan: Time and Space Efficient Concolic Execution via Dynamic Data-Flow Analysis},
  booktitle =    {{USENIX} Security Symposium (Security)},
  year =         2022,
  url =          {https://www.usenix.org/conference/usenixsecurity22/presentation/chen-ju},
  publisher =    {{USENIX} Association},
  month =        aug,
}
```
