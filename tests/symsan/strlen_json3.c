// Test: strlen constraint in JSON context
// When shrinking, DELETE should remove bytes so JSON remains valid
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf '{"name":"HELLO WORLD HELLO WORLD","age":25}' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN %s
//
// The RGD path is a separate solver stack -- afltest runs i2s/jigsaw/z3 over
// parsers/rgd-parser.cpp, fgtest runs solvers/z3-ts.cpp -- and only the RGD one
// is what a fuzzer executes.  This is the test that says why a length answer has
// to be a splice.  The string whose length is being constrained is not
// NUL-terminated data at all: the program finds the closing quote and overwrites
// it, so the "terminator" i2s sees is a byte the file spends on structure.
// Satisfying strlen by writing a NUL at the new end therefore satisfies the node
// and destroys the document -- the quote is gone, strchr returns NULL, and the
// program prints "Malformed JSON" without ever reaching the branch.  Deleting the
// six characters instead leaves the quote where it was, one field shorter.
//
// The length answer is id-0-0-2; the two before it are the other two branches on
// the way in, both answered correctly.  id-0-0-0 breaks the key so the strstr
// misses ("Field not found").  id-0-0-1 clears every quote at or after the key so
// the strchr misses ("Malformed JSON - no closing quote") -- that haystack is a
// SLICE of the buffer rather than a string of its own, which i2s used to decline,
// so this input is why the index here is 2 and not 1.
// CHECK-RGD-FILE: {"name":"HELLO","age":25}
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: FileCheck --check-prefix=CHECK-RGD-FILE %s < %t.rgd.out/id-0-0-2

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[256];
  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 1;
  }

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = '\0';
  fclose(f);

  printf("Input: %s\n", buf);

  // Find name value
  char *start = strstr(buf, "\"name\":\"");
  if (!start) {
    printf("Field not found\n");
    return 0;
  }

  start += 8; // skip "name":"

  // Find closing quote
  char *end = strchr(start, '"');
  if (!end) {
    printf("Malformed JSON - no closing quote\n");
    return 0;
  }

  // Temporarily null-terminate for strlen
  *end = '\0';
  size_t len = strlen(start);
  *end = '"';

  printf("Name value: \"%.*s\" (len=%zu)\n", (int)len, start, len);

  if (len == 5) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: Found name with exactly 5 chars!\n");
  } else {
    // CHECK-ORIG: NOT-5
    printf("NOT-5: len = %zu\n", len);
  }

  return 0;
}
