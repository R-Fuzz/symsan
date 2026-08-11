# A AFL++ plugin for using SYMSAN as a custom mutator

**The recommended integration is now the LibAFL one under
[`bindings/rust/`](../../bindings/rust/README.md)** — see the
[hybrid fuzzing how-to](../../bindings/rust/HYBRID_FUZZING.md) for an end-to-end
walkthrough. This AFL++ custom-mutator plugin predates it and is kept as a
C++-native alternative; the two share the same solver ladder (i2s → jigsaw → z3).

## HowTo

A quick guide to how to use the plugin:

### Compilation

Tested on Ubuntu 24.04 with LLVM 18 (the main branch tracks LLVM-18).

First, install dependencies:

```
apt-get update
apt-get install -y lsb-release wget software-properties-common gnupg
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 18
apt-get install -y cmake libc++-18-dev libc++abi-18-dev libunwind-18 python3-minimal python-is-python3 zlib1g-dev git gdb joe
apt-get install -y libz3-dev libgoogle-perftools-dev
```

Next, download and build AFL++:

```
git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus /workdir/aflpp
export LLVM_CONFIG=llvm-config-18
cd /workdir/aflpp && CC=clang-18 CXX=clang++-18 make source-only && make install
```

Next, download symsan and build

```
git clone https://github.com/R-Fuzz/symsan /workdir/symsan
cd symsan/ && mkdir -p build && \
  cd build && CC=clang-18 CXX=clang++-18 cmake -DAFLPP_PATH=/workdir/aflpp ../  && \
  make -j && make install
```

### Build target binaries

You need to compile two binaries: one for normal fuzzing and one for symbolic tracing

For the normal fuzzing binary, you can set `AFL_LLVM_CMPLOG=0` to disable `cmplog` as the plugin does a similar job.
Please refer to the AFL++ manual for building options.

For the symbolic tracing binary, set the following env options

* `KO_CC=clang-18`: use clang-18 as the C compiler, because SymSan is compiled as a LLVM-18 pass
* `KO_CXX=clang++-18`: using clang++-18 as the C++ compiler
* `KO_USE_FASTGEN=1`: using the out-of-process solving mode (i.e., decoupled tracing and solving)
* `KO_DONT_OPTIMIZE=1` (optional): keep the original optimization level, otherwise override with `-O3`
* `KO_NO_NATIVE_ZLIB` (optional): if you're using instrumented libz
* `KO_USE_NATIVE_LIBCXX` (optional): if you want to use the native, *uninstrumented* standard C++ lib, the default option uses the instrumented `libc++` and `libc++-abi`.

To build the target, set `CC=/path/to/symsan/bin/ko-clang` and `CXX=/path/to/symsan/bin/ko-clang++`.
If the configuration fails, you can set `KO_CONFIG=1`, and unset it after configuration.

### Fuzz

After the two binaries are built, use AFL++ to fuzz it, use the following env options
to load the plugin and control its behavior:

* `AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/symsan/bin/libSymSanMutator.so`: load the plugin
* `SYMSAN_TARGET=/path/to/symsan-instrumented-binary`: symbolic tracing binary
* `AFL_DISABLE_TRIM=1` (optional): for some targets (e.g., the `mini` test case), you may want to disable trim
* `AFL_CUSTOM_MUTATOR_ONLY=1` (optional): if you only want to test the plugin
* `SYMSAN_OUTPUT_DIR=/none/default/dir` (optional): a different directory to store temporary outputs from SymSan
* `SYMSAN_USE_JIGSAW=1` (optional): use JIGSAW as the solver
* `SYMSAN_USE_Z3=1` (optional): use Z3 as the solver
* `SYMSAN_NO_I2S=1` (optional): drop the input-to-state solver, which otherwise
  always runs first. Only useful for measuring what the solvers behind it
  contribute; with the two above unset it leaves nothing to solve with
* `SYMSAN_USE_NESTED=1` (optional): consider nested branches when constructing a solving task

## Some high-level design

The custom mutator works in two main steps:

1. In the interface function `afl_custom_fuzz_count`, the plugin spawns
   a symsan-instrumented binary to collect the symbolic traces (i.e., the tracing
   stage in libafl). For each event it wants to handle, it constructs a *solving task*.

2. In the interface function `afl_custom_fuzz`, the plugin fetches a *solving task*,
   solves it, and generate a new input (i.e., the mutation stage in libafl).
   The newly generated input is then evaluated with the main fuzzing binary.
   If the input is saved, the task is considered as successfully solved.

## Extensions

One main motivation to move to libafl and afl++ custom mutator is to make the
concolic execution stage more extensible (than in fastgen). Following are some
interfaces that can be customized:

* `rgd::CovManager` is in charge of determine whether an event from symsan should
  be used to construct a solving task. The default one uses branch coverage
  (similar to sancov `trace-pc-guard`) to filter events.

* `rgd::TaskManager` is in charge of scheduling *solving tasks*. The default one
  is a simple FIFO queue.

* `rgd::Solver` is in charge of solving a solving task. Right now there are three
  solvers, which works in a layered manner (i2s->jigsaw->z3):
  if a task is solved by an earlier solver, it will skip the next solver; otherwise the next solver is invoked.
    * The default one is a simple I2S solver, which uses tracing results to map input bytes to comparison
      operands and generate a solution based on potential
      [input-to-state correspondence](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/).
    * JIGSAW, which is our [JIT-based constraint solver](https://github.com/R-Fuzz/jigsaw).
    * Z3

