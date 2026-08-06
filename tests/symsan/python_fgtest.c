// bindings/python/test.py is fgtest written against the python binding, and
// this is the test that says so: the same target, the same TAINT_OPTIONS and
// the same seeds through both drivers, then `diff` on what they wrote.
//
// Equality against the C driver is the assertion worth making, rather than
// "python produced some inputs".  Everything the wrapper does -- parse a
// condition, drain a payload, solve, apply a solution -- has a C original that
// is already covered by the rest of this suite, so a byte-difference in the
// generated inputs points at the binding and nothing else.  It is also the only
// thing that catches a payload that goes undrained: the stream desyncs, every
// later event is misread, and the run still exits 0 with a plausible-looking
// (but shorter) list of outputs.
//
// Hence the target below.  It emits all four of the event types that carry a
// payload the reader has to account for -- a table lookup, a tainted GEP index,
// a memcmp with concrete content, and plain conditions -- and its one solvable
// goal is the memcmp, which comes *last*.  So a reader that mishandles the
// table contents or the GEP record does not merely lose that record: it loses
// the goal, and the replay stops printing "Good".
//
// The hex[] lookup has to feed strncmp rather than a comparison against a
// constant.  `hex[i] == 'e'` is folded by instcombine into `i == 14` (it scans
// the table for the constant and rewrites the compare over the index), the
// global is dropped, and there is no table event left to drain.
//
// REQUIRES: pysymsan
// RUN: rm -rf %t.c.out %t.py.out %t.mc.out %t.mp.out
// RUN: mkdir -p %t.c.out %t.py.out %t.mc.out %t.mp.out
// RUN: python -c'print("A"*24, end="")' > %t.bin
// RUN: python -c'print("B"*24, end="")' > %t2.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -o %t.fg %s

// One seed, and the branch it solves for actually flips.
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.py.out" \
// RUN:     env PYTHONPATH=%pysymsan-path %python \
// RUN:     %S/../../bindings/python/test.py %t.fg %t.bin | FileCheck --check-prefix=CHECK-GEN %s
// RUN: %t.uninstrumented %t.py.out/id-0-0-0 | FileCheck --check-prefix=CHECK-FLIP %s

// The same seed through fgtest, and the two agree on every byte they wrote.
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.c.out" \
// RUN:     %fgtest %t.fg %t.bin | FileCheck --check-prefix=CHECK-GEN %s
// RUN: diff -r %t.c.out %t.py.out

// Two seeds: one fork server, one staged input path, and a session number per
// seed so the outputs of the second do not overwrite the first's.  Equality
// here covers the fork-server path as well -- python_forkserver.c checks that
// the server serves the right input, this checks the driver around it agrees
// with the C one about which session and index each answer belongs to.
// RUN: env TAINT_OPTIONS="output_dir=%t.mc.out" %fgtest %t.fg %t.bin %t2.bin
// RUN: env TAINT_OPTIONS="output_dir=%t.mp.out" \
// RUN:     env PYTHONPATH=%pysymsan-path %python \
// RUN:     %S/../../bindings/python/test.py %t.fg %t.bin %t2.bin
// RUN: diff -r %t.mc.out %t.mp.out
// RUN: ls %t.mp.out | FileCheck --check-prefix=CHECK-SESSIONS %s

// CHECK-GEN: generate #0 output (size: 24 -> 24)
// CHECK-SESSIONS: id-0-0-0
// CHECK-SESSIONS: id-0-1-1

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"

// Read-only, integer elements, never stored to: what TaintPass looks for when
// it decides a load through a symbolic index is a table lookup rather than an
// ordinary load off a concrete address.
static uint8_t hex[16] = {'0','1','2','3','4','5','6','7',
                          '8','9','a','b','c','d','e','f'};

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buf[24] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  // table event: the loaded byte carries a tlookup label, which reaches the
  // solver through strncmp's content.  Unsolvable here (tlookup is i2s-only,
  // and this suite's drivers use z3) -- it is on the stream to be drained.
  uint8_t tmp[5];
  for (int i = 0; i < 4; i++)
    tmp[i] = hex[buf[i] % 16];
  tmp[4] = 0;
  if (strncmp((char *)tmp, "beef", 4) == 0)
    printf("Hex\n");

  // gep event: a symbolic index into a local array.
  uint8_t lut[32] = {0};
  lut[buf[5] & 0x1f] = 1;
  if (lut[7])
    printf("Gep\n");

  // memcmp event, and the goal.  Last, so nothing before it can be dropped
  // without dropping this too.
  if (memcmp(buf + 8, "SYMSANOKGO", 10) == 0) {
    // CHECK-FLIP: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
  return 0;
}
