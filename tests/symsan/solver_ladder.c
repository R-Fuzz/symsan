// The solver ladder is three independent rungs, and each one can be turned off.
//
// i2s is the odd one: it used to be hardcoded first and unconditional, so the
// only knobs were SYMSAN_USE_JIGSAW and SYMSAN_USE_Z3 and there was no way to
// ask what either of them could do on its own.  SYMSAN_NO_I2S drops it, and
// this test pins both halves of that -- that the knob really removes the
// solver, and that removing it does not quietly take the rest of the ladder
// with it.
//
// The guard is the simplest thing i2s exists for: a 4-byte input word against a
// constant.  Which is also why the negative case is worth having.  Every rung
// can crack this one, so a broken knob looks exactly like a working one unless
// something checks the run where NOTHING should come out.
//
// This is plumbing, not solving: the knob crosses ConcolicConfig,
// symsan_config_t and the Rust Config, and a break anywhere along it turns
// "z3 is off by default" into "everything is off by default" without a single
// test going red.
//
// RUN: python -c'import sys; sys.stdout.buffer.write(b"\x00"*8)' > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s

// The default ladder is i2s, and i2s alone gets this.
// RUN: rm -rf %t.i2s && mkdir -p %t.i2s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.i2s" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.i2s/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

// Drop it with nothing behind it and the trace still runs -- the constraint is
// still parsed into a task -- but there is no solver left to answer it.
// RUN: rm -rf %t.none && mkdir -p %t.none
// RUN: env SYMSAN_NO_I2S=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.none" %afltest %t.fg %t.bin
// RUN: ls %t.none | FileCheck --check-prefix=CHECK-NONE --allow-empty %s
// CHECK-NONE-NOT: id-

// Drop it with jigsaw behind it and jigsaw answers it by itself, which is the
// measurement the knob is for.
// RUN: rm -rf %t.jigsaw && mkdir -p %t.jigsaw
// RUN: env SYMSAN_NO_I2S=1 SYMSAN_USE_JIGSAW=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.jigsaw" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.jigsaw/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[8] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  uint32_t x;
  memcpy(&x, buf, sizeof x);

  if (x == 0xdeadbeefu) {
    // CHECK-GEN: Good
    printf("Good\n");
    return 0;
  }

  // CHECK-ORIG: Bad
  printf("Bad\n");
  return 0;
}
