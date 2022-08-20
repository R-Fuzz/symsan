// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print"\x00\x00\x00\x00"' > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN1 %s
// RUN: %t.uninstrumented %t.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN2 %s
// RUN: %t.uninstrumented %t.out/id-0-0-2 | FileCheck --check-prefix=CHECK-GEN3 %s
// RUN: %t.uninstrumented %t.out/id-0-0-3 | FileCheck --check-prefix=CHECK-GEN4 %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

struct point_t {
  int x;
  int y;
};

struct graph_t {
  struct point_t points[0x100];
};

struct set_t {
  struct graph_t graph[0x100];
};

int main (int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  int index = 0;
  char buf[0x100];
  struct point_t points[0x100];
  struct graph_t graph;
  struct set_t set;

  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(&index, 1, sizeof(index), fp);

  if (&buf[index] == &buf[1]) {
    // CHECK-GEN1: Good1
    printf("Good1\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  if (&points[index] == &points[2]) {
    // CHECK-GEN2: Good2
    printf("Good2\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  if (&graph.points[index] == &graph.points[3]) {
    // CHECK-GEN3: Good3
    printf("Good3\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  if (&set.graph[index].points[4] == &set.graph[4].points[4]) {
    // CHECK-GEN4: Good4
    printf("Good4\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  fclose(fp);
}
