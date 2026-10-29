// A vector GEP -- the loop vectorizer's `getelementptr T, ptr %p, <2 x i64>`,
// a vector of pointers (v8's turboshaft Graph::AllocateNewBlocks) -- on a
// symbolic base must give valid IR.  TaintPass handed the GEP to
// __taint_gep_offset through a bitcast of <2 x ptr> to ptr, which llc rejects
// ("invalid cast opcode"); its vector indices would also have reached the
// bounds calls as i64.  A vector GEP now keeps its base's shadow.
//
// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: printf '\003' > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O2 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.fg %t.bin | FileCheck %s
// CHECK: 48

#include <stdio.h>

struct blk {
  long a, b;
};

static struct blk pool[64];

__attribute__((noinline)) void fill(struct blk **__restrict out,
                                    struct blk *__restrict base, int n) {
  for (int i = 0; i < n; ++i)
    out[i] = &base[i];
}

int main(int argc, char **argv) {
  unsigned char c = 0;
  FILE *f = fopen(argv[1], "rb");
  if (!f || fread(&c, 1, 1, f) != 1)
    return 1;
  fclose(f);
  struct blk *out[16];
  fill(out, &pool[c & 15], argc + 15);
  printf("%ld\n", (long)((char *)out[0] - (char *)pool));
  return 0;
}
