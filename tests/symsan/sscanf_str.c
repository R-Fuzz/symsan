// Test: sscanf %s copies the matched input bytes' labels to the output buffer,
// so a downstream strcmp on the scanned string is solvable.
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: printf 'aaaaa' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  char buf[128] = {0};
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = '\0';
  fclose(f);

  char s[64] = {0};
  sscanf(buf, "%s", s);
  if (strcmp(s, "hello") == 0) {
    // CHECK-GEN: SCANF-STR-OK
    printf("SCANF-STR-OK\n");
  } else {
    // CHECK-ORIG: SCANF-STR-NO
    printf("SCANF-STR-NO\n");
  }
  return 0;
}
