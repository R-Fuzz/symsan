// P0: lookup table embedded as a field of a readonly global struct.
//
// Expat's BYTE_TYPE is ((normal_encoding*)enc)->type[byte].  The global's
// value type is a StructType, not an ArrayType, so the old finder skipped it
// and the load stayed concrete.  With struct-field tables the load is a
// tlookup and i2s inverts "which index yields BT_TARGET".
//
// %afltest only: tlookup is an i2s-only op.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: echo -n "A" > %t.bin
// RUN: clang -O0 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include "lib.h"

enum { BT_OTHER = 0, BT_NAME = 1, BT_DIGIT = 2, BT_LT = 3 };

struct encoding {
  int min_bytes; // pad so type[] is not at offset 0
  unsigned char type[256];
};

// '<' -> BT_LT; digits -> BT_DIGIT; letters -> BT_NAME; else BT_OTHER
static const struct encoding ascii_encoding = {
    1,
    {[0 ... 255] = BT_OTHER,
     ['0' ... '9'] = BT_DIGIT,
     ['A' ... 'Z'] = BT_NAME,
     ['a' ... 'z'] = BT_NAME,
     ['<'] = BT_LT},
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

  // Direct GEP of a struct-field table (P0): base is the global itself.
  switch (ascii_encoding.type[buff[0]]) {
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
