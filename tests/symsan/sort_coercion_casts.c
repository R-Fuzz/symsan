// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'AA/AAAAA')" > %t.bin
// RUN: clang -O2 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O2 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-SOL %s

// Casts and bitwise ops over values the parser holds in another sort.  A
// comparison is a Bool, and ZExt turned one into a bitvector but SExt did not:
// `x + (c == 10 ? -1 : 0)` is `sext i1 (icmp)` (ext4_attr_store).  A strchr
// result is an Int, and so is a difference with it, which Trunc extract()ed
// (`len = next - cp` in __xlate_proc_name), and an Xor -- the signed-overflow
// UB check on that difference XORs the pointers -- applied to Ints.  Each
// threw "sort is not a bit-vector" or "wrong sort", and the branch was lost.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static void show(const char *what, long v) {
  printf("%s %ld\n", what, v);
}

// an int, so that the difference is truncated to one
__attribute__((noinline)) static void show_int(const char *what, int v) {
  printf("%s %d\n", what, v);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[16] = {0};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  fread(buf, 1, 8, fp);
  fclose(fp);

  int adj = buf[7] == 10 ? -1 : 0;
  int v = buf[6] + adj;
  // CHECK-ORIG: v 65
  show("v", v);
  if (v == 'A' - 1) {
    // CHECK-ORIG-NOT: Good1
    // CHECK-SOL-DAG: Good1
    printf("Good1\n");
  }

  char *p = strchr(buf, '/');
  if (p) {
    int len = p - buf;
    // CHECK-ORIG: len 2
    show_int("len", len);
    if (len == 4) {
      // CHECK-ORIG-NOT: Good2
      // CHECK-SOL-DAG: Good2
      printf("Good2\n");
    }
    unsigned long x = (unsigned long)(p - buf) ^ 1UL;
    show("x", x);
    if (x == 6) {
      // CHECK-ORIG-NOT: Good3
      // CHECK-SOL-DAG: Good3
      printf("Good3\n");
    }
  }
  return 0;
}
