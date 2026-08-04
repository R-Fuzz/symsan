// Test strlen with null terminator from input file
// The input has embedded null, so strlen stops there
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'HELLO WORLD\0extra' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
//
// The RGD path is a separate solver stack -- afltest runs i2s/jigsaw/z3 over
// parsers/rgd-parser.cpp, fgtest runs solvers/z3-ts.cpp -- and only the RGD one
// is what a fuzzer executes.  This is the flavour where the terminator is an
// input byte rather than one the program stored, which the runtime records as
// StrLen's null_from_input flag, and it is here to pin what the shrink does with
// it: the six characters before it are deleted and the terminator itself SURVIVES
// -- it is the same byte, six positions lower, still terminating the string, with
// "extra" still behind it.  z3-ts consults null_from_input to decide whether to
// write a terminator of its own; i2s does not have to, because it moves the
// existing one rather than replacing it.
// CHECK-RGD-FILE: HELLO{{.}}extra
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: FileCheck --check-prefix=CHECK-RGD-FILE %s < %t.rgd.out/id-0-0-0

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) return 1;

  char buf[64];
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;

  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  // Don't add null - rely on the null from input
  fclose(f);

  // Only call strlen if we know there's a null in the buffer
  size_t len = strlen(buf);
  printf("strlen: %zu\n", len);

  if (len == 5) {
    // CHECK-GEN: SUCCESS
    printf("SUCCESS: strlen == 5\n");
  } else {
    // CHECK-ORIG: NOT-5
    printf("NOT-5: strlen = %zu\n", len);
  }

  return 0;
}
