// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration: finds last semicolon (backward search)
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration: finds colon before the semicolon (forward search via pointer)
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test mixed chain: strrchr (backward) followed by strchr (forward via pointer)
// t1 = strrchr(buf, ';');  // find LAST semicolon
// t2 = strchr(buf, ':');   // find first colon
// if (t2 < t1) ...         // verify colon is before semicolon
// This tests combining last_indexof and indexof with comparison

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

  char buf[20];
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  buf[19] = '\0';

  // First: strrchr finds LAST ';' (backward search / last_indexof)
  char *t1 = strrchr(buf, ';');
  if (t1) {
    // Second: strchr finds first ':' (forward search)
    char *t2 = strchr(buf, ':');
    if (t2 && t2 < t1) {
      // CHECK-GEN: Found colon before last semicolon
      printf("Found colon before last semicolon (colon at %ld, semicolon at %ld)\n",
             (long)(t2 - buf), (long)(t1 - buf));
    } else if (t2) {
      printf("Found both but colon not before semicolon\n");
    } else {
      printf("Found semicolon but no colon (semicolon at %ld)\n",
             (long)(t1 - buf));
    }
  } else {
    // CHECK-ORIG: No semicolon
    printf("No semicolon\n");
  }
  return 0;
}
