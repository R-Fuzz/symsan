// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'\x00\x00\x00\x00'*3)" > %t.bin
// RUN: clang++ -fsanitize=bounds -o %t.ubsan %s
// RUN: env KO_USE_FASTGEN=1 KO_SOLVE_UB=1 %ko-clang++ -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out solve_ub=1" %fgtest %t.fg %t.bin
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-0 2>&1 FileCheck %s --check-prefix=CHECK-A2
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-1 2>&1 FileCheck %s --check-prefix=CHECK-A2
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-3 2>&1 FileCheck %s --check-prefix=CHECK-B-3
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-4 2>&1 FileCheck %s --check-prefix=CHECK-B-3
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-7 2>&1 FileCheck %s --check-prefix=CHECK-C-4
// RUN: not env UBSAN_OPTIONS="halt_on_error=1" %t.ubsan %t.out/id-0-0-8 2>&1 FileCheck %s --check-prefix=CHECK-C-4

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return 0;
  }

  int i = 0, j = 0, k = 0;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&i, sizeof(i), 1, fp);
  chk_fread(&j, sizeof(j), 1, fp);
  chk_fread(&k, sizeof(k), 1, fp);
  fclose(fp);

  int arr[2][3][4] = {};

  return arr[i][j][k];
  // CHECK-A-2: bounds.cpp:[[@LINE-1]]:10: runtime error: index {{.*}} out of bounds for type 'int[2][3][4]'
  // CHECK-B-3: bounds.cpp:[[@LINE-2]]:10: runtime error: index {{.*}} out of bounds for type 'int[3][4]'
  // CHECK-C-4: bounds.cpp:[[@LINE-3]]:10: runtime error: index {{.*}} out of bounds for type 'int[4]'
}
