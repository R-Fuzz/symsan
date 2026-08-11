// Test: shrinking strlen by deleting bytes
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'HELLO WORLD' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// The RGD path is a separate solver stack -- afltest runs i2s/jigsaw/z3 over
// parsers/rgd-parser.cpp, fgtest runs solvers/z3-ts.cpp -- and only the RGD one
// is what a fuzzer executes.  Its arm asserts WHICH bytes went, which is what
// the hex dump this test already prints is for: the six characters between the
// new end and the old one are DELETED, so the buffer is "HELLO" and nothing
// else.  Writing a NUL over the space instead would satisfy strlen just as well
// and leave "WORLD" sitting behind it, which is the right answer only if the
// bytes after a string are positional; for the delimited formats string solving
// is actually for, it corrupts the document -- see strlen_json3.c, where that
// edit destroys the closing quote the field needs.
// CHECK-RGD: contents (hex): 48 45 4c 4c 4f{{ *$}}
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-RGD %s

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[64];
  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 1;
  }

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = '\0';
  fclose(f);

  // This is the strlen we're solving
  size_t len = strlen(buf);
  printf("strlen returned: %zu\n", len);

  // Show what bytes are actually in the buffer
  printf("Buffer contents (hex): ");
  for (size_t i = 0; i < 15 && i < n; i++) {
    printf("%02x ", (unsigned char)buf[i]);
  }
  printf("\n");

  if (len == 5) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: Found input with strlen=5\n");
  } else {
    // CHECK-ORIG: NOT-5
    printf("NOT-5: strlen=%zu\n", len);
  }

  return 0;
}
