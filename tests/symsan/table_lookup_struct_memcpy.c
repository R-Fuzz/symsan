// P0 + escaping address: const struct table that is memcpy'd elsewhere.
//
// Expat's latin1_encoding is `static const` but memcpy'd into unknown-encoding
// buffers.  GlobalStatus::analyzeGlobal then bails out ("unanalyzable"), and a
// NotStored-only check would skip the type[256] field.  isConstant() must still
// register the table so direct ascii_encoding.type[i] becomes tlookup.
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
#include <string.h>
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

// Sink so the memcpy is not DCE'd; mirrors XmlInitUnknownEncoding.
static struct encoding unknown_scratch;

__attribute__((noinline)) static void copy_encoding(struct encoding *dst) {
  memcpy(dst, &ascii_encoding, sizeof(ascii_encoding));
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  uint8_t buff[1] = {0};
  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buff, 1, sizeof(buff), fp);
  fclose(fp);

  copy_encoding(&unknown_scratch);
  (void)unknown_scratch.min_bytes;

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
