// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// First iteration: finds first colon
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// Second iteration: finds semicolon before the colon (backward search via pointer chain)
// RUN: env TAINT_OPTIONS="taint_file=%t.out/id-0-0-0 output_dir=%t.out session_id=1 enum_gep=0" %fgtest %t.fg %t.out/id-0-0-0
// RUN: %t.uninstrumented %t.out/id-0-1-1 | FileCheck --check-prefix=CHECK-GEN %s

// Test mixed chain: strchr (forward) followed by strrchr (backward from result)
// t1 = strrchr(buf, ':');     // find last colon
// t2 = strchr(t1, ';'); // find first semicolon after the colon
// This tests combining last_indexof (strrchr) with indexof (strchr) via pointer chain

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[256] = {0};
  FILE* fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  buf[n] = '\0';

  // First: strrchr finds last ':' (backward search)
  char *t1 = strrchr(buf, ':');
  if (t1) {
    // Second: strchr finds first ';' after the colon (forward search from t1)
    char *t2 = strchr(t1, ';');
    if (t2) {
      // CHECK-GEN: Found semicolon after colon
      printf("Found semicolon after colon (colon at %ld, semicolon at %ld)\n",
             (long)(t1 - buf), (long)(t2 - buf));
    } else {
      printf("Found colon but no semicolon after it (colon at %ld)\n",
             (long)(t1 - buf));
    }
  } else {
    // CHECK-ORIG: No colon
    printf("No colon\n");
  }
  return 0;
}
