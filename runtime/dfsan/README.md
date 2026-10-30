# SymSan and UCSan runtimes

SymSan (concolic execution) and UCSan (under-constrained execution) can run
alone, or together.  That is a design constraint, and the build keeps to it:

| Configuration | ko-clang | Passes | Runtime | Sources |
|---|---|---|---|---|
| SymSan alone: whole-program concolic execution | no `METADATA` | TaintPass | `libsymsan_rt` | dfsan*.cpp |
| UCSan alone: pure UC execution, e.g. with a fuzzer | `METADATA` + `KO_USE_UCSAN_ONLY` | UCSanPass | `libucsan_rt` | ucsan*.cpp |
| Together | `METADATA` | UCSanPass, then TaintPass | `libdfsan_rt` | both, `-DUSE_UCSAN_CUSTOM` |

`USE_UCSAN_CUSTOM` marks the combined build.  Code that needs both halves
belongs under it, or in dfsan.cpp, which is never in `libucsan_rt`.  That
covers bridges from UCSan's state to SymSan's, and anything that exists for
TaintPass's callers.  Don't add a weak stub to ucsan.cpp so that such code
links in `libucsan_rt`: UCSan alone should not carry it.

## Custom wrappers: who calls which

A libc function with a custom wrapper is called as `__<prefix>_<name>`, with
its arguments' labels appended.  There are two label ABIs: dfsan's
(`dfsan_label`, 32-bit) and UCSan's (`ucsan_label`, 16-bit).

| Caller | Wrapper | ABI | Defined in |
|---|---|---|---|
| SymSan alone, any instrumented code | `__dfsw_X` | dfsan's | dfsan_custom.cpp |
| UCSan alone, in-scope code | `__dfsw_X` | UCSan's | ucsan_custom.cpp |
| Together, in-scope code (UCSanPass) | `__dfsw_X` | UCSan's | ucsan_custom.cpp, for a function ucsan_abilist.txt lists `custom`; dfsan_custom.cpp's for the rest |
| Together, library code (TaintPass alone) | `__dfsl_X`, for a function ucsan_abilist.txt lists `custom` | dfsan's | ucsan_custom.cpp, the adapters under `USE_UCSAN_CUSTOM` |
| Together, library code (TaintPass alone) | `__dfsw_X`, for any other function | dfsan's | dfsan_custom.cpp |

In the combined build, a function UCSan wraps (the allocators, the simulated
file I/O) has one `__dfsw_` symbol, UCSan's.  dfsan_custom.cpp skips its own
definition under `USE_UCSAN_CUSTOM`.  In-scope code calls that symbol with
UCSan's ABI.

Some code linked into a UCSan binary is TaintPass's alone, and calls with
dfsan's ABI instead:
- the instrumented libc++ (`libc++-ucsan.a`, built by `libcxx/rebuild.sh
  --ucsan` with `KO_UCSAN_LIB`, i.e. TaintPass `-taint-ucsan-lib`);
- a body UCSanPass leaves to TaintPass (function attribute `"ucsan-lib"`).

It cannot call the same symbol.  UCSan's `__dfsw_malloc` writes a 16-bit
result label into the caller's 32-bit slot.  libc++'s `operator new` then
read the label 0xffff000b, and `__taint_union` segfaulted reading past the
label table.  With a zero high half the bug is silent: an object label read
as an input byte's.

So TaintPass, given UCSan's abilist (`-taint-ucsan-abilist`, which ko-clang
passes under UCSan or `KO_UCSAN_LIB`), calls these functions as `__dfsl_X`
in library code.  `l` is for "called from library code".  The adapter takes
dfsan's ABI and calls UCSan's `__dfsw_X`.  Library code and in-scope code
therefore share one heap (UCSan's) and one simulated file.  A `FILE*`
in-scope code got from UCSan's `fopen` is a handle libc++ can read from.

File I/O is the exception: library code's own files are real.  A library
`open`/`fopen` is a real one, and a read, seek or close goes to UCSan's
wrapper only for a handle UCSan's made (an fd from 1000, a `FILE*` from
0xFAFE0000) or stdin (fd 0, unless library code opened fd 0 itself because
stdin was closed).  Any other handle goes to dfsan_custom.cpp's wrapper,
which the combined runtime compiles as `__dfsr_X` ("real"), since UCSan owns
the `__dfsw_` name: real I/O, labeled only for the `taint_file`, which a UCSan
run has none of.  The bytes read are initialized in UCSan's shadow too.  v8's
fixture, setting up an Isolate out of scope, seeds its random number
generators from `/dev/urandom`; read as UCSan's simulated file, the seeds
were symbolic, and so were the mmap hints derived from them, and the solver
spent its time there.  In-scope code is not dispatched: UCSan's `read`
reads its simulated file whatever the fd, a real one library code opened
included.  A C++ program in scope whose input is a file read through
`std::ifstream` (libc++.a's `basic_filebuf`) now reads the real file.

The adapter passes no UCSan labels: library code keeps none.  It returns the
dfsan label UCSan's wrapper set in retval TLS slot 0, which is the label an
in-scope call reads.  It clears the slot first, because not every path of
UCSan's wrappers sets it.  A library `free` therefore has no UCSan label, and
UCSan's `free` does nothing with it.  UCSan never really frees, so an object
freed inside libc++ is not tracked for use-after-free.

This is not specific to libc++: any TaintPass-only library linked into a
combined binary works the same way.  A call to a UCSan `custom` function
that has no adapter yet fails to link, on an undefined `__dfsl_<name>`.  Add
the adapter to ucsan_custom.cpp, after the others.  Its signature is the
dfsan one, as dfsan_custom.cpp declares `__dfsw_<name>`.

The tests:
- `tests/symsan/ucsan_lib_dfsl.c` checks which names TaintPass emits;
- `tests/ucsan/test/libcxx_malloc.cpp` runs a libc++ allocation end to end.
