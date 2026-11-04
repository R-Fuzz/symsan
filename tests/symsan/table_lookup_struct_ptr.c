// P1: same struct-field table, reached through an encoding pointer that
// aliases one of several readonly globals (expat's BYTE_TYPE(enc, p)).
//
// getUnderlyingObject(enc) is not a GlobalVariable when enc is a parameter or
// a select between encodings; matchTableThroughPointer requires every
// underlying object to be a registered table-bearing global with the same
// field layout.
//
// %afltest only: tlookup is an i2s-only op.
//
// -O1 keeps the select feeding the GEP instead of spilling it through an
// alloca (at -O0 getUnderlyingObjects sees the alloca and P1 correctly
// declines -- same as a heap encoding pointer).
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "A" > %t.bin
// RUN: clang -O1 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O1 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include "lib.h"

enum { BT_OTHER = 0, BT_NAME = 1, BT_DIGIT = 2, BT_LT = 3 };

struct encoding {
  int min_bytes;
  unsigned char type[256];
};

static const struct encoding ascii_encoding = {
    1,
    {[0 ... 255] = BT_OTHER,
     ['0' ... '9'] = BT_DIGIT,
     ['A' ... 'Z'] = BT_NAME,
     ['a' ... 'z'] = BT_NAME,
     ['<'] = BT_LT},
};

// Distinct from ascii so LLVM cannot merge the two globals (which would
// collapse the select into a single pointer and miss the P1 path).
static const struct encoding latin1_encoding = {
    1,
    {[0 ... 255] = BT_OTHER,
     ['0' ... '9'] = BT_DIGIT,
     ['A' ... 'Z'] = BT_NAME,
     ['a' ... 'z'] = BT_NAME,
     ['<'] = BT_LT,
     [0xA0] = BT_NAME},
};

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[1] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  // Select between two identical-layout encoding globals so the GEP base is
  // not a constant GlobalVariable, but every underlying object still is
  // (matchTableThroughPointer).  volatile keeps the select from folding away
  // at -O0.  A non-inlined helper would turn the base into a Call/Argument and
  // fail P1 -- same as expat's BYTE_TYPE macro, which expands at the use site.
  volatile int which = 0;
  const struct encoding *enc =
      which ? &ascii_encoding : &latin1_encoding;

  switch (enc->type[buff[0]]) {
  case BT_LT:
    // CHECK-GEN: Good
    printf("Good\n");
    return 0;
  default:
    // CHECK-ORIG: Bad
    printf("Bad\n");
    return 0;
  }
}
