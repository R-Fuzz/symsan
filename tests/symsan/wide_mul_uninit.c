// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00')" > %t.bin
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin trace_bounds=1" %t.fg %t.bin

// Under trace_bounds a stack object's bytes start labeled kInitializingLabel
// (-1), and a 128-bit operation on one reached __taint_union's WideConst
// early-out, which looked the label up (is_wide_const) before the -1 check
// below it: a read past the union table, SIGSEGV.  v8's rapidhash
// (rapid_mul128) does this in V8::Initialize, hashing a struct whose padding
// was never written.
#include <stdio.h>

int main(int argc, char **argv) {
  unsigned long words[2];
  words[0] = 1;  // words[1] is never written
  unsigned __int128 a = words[1];
  volatile unsigned long sink =
      (unsigned long)(a * (unsigned __int128)0x9E3779B97F4A7C15ULL);
  (void)sink;
  return 0;
}
