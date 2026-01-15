// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("A"*20)' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Implementation matching xmlStrsub signature
// Extracts substring starting at 'start' with length 'len'
char *xmlStrsub(const char *str, int start, int len) {
  if (str == NULL) return NULL;
  if (start < 0) return NULL;
  if (len < 0) return NULL;

  // Skip to start position
  int i;
  for (i = 0; i < start; i++) {
    if (*str == 0) return NULL;
    str++;
  }
  if (*str == 0) return NULL;

  // Duplicate len characters (like xmlStrndup)
  size_t actual_len = strlen(str);
  if ((size_t)len > actual_len) len = actual_len;

  char *ret = (char *)malloc(len + 1);
  if (ret == NULL) return NULL;
  memcpy(ret, str, len);
  ret[len] = '\0';
  return ret;
}

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

  // Extract substring from position 5, length 5
  // If input is "xxxxxhello...", substr should be "hello"
  char *sub = xmlStrsub(buf, 5, 5);
  if (sub != NULL) {
    if (strcmp(sub, "hello") == 0) {
      // CHECK-GEN: Found hello
      printf("Found hello\n");
    } else {
      // CHECK-ORIG: No match
      printf("No match\n");
    }
    free(sub);
  } else {
    printf("Substr failed\n");
  }

  return 0;
}
