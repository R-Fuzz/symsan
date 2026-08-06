// The SymSan runtime must contribute no static constructors.
//
// dfsan_init is registered in .preinit_array, and the fork server's fork point
// sits inside it (dfsan.cpp, InitializeSymSanForkServer).  A static object with
// a nontrivial constructor gets an .init_array entry instead, and .init_array
// runs *after* all of .preinit_array -- so such a constructor runs on the wrong
// side of the fork, separately in every forked child, which is exactly the cost
// the fork server exists to amortize away.
//
// That was #139: the union hash table was `union_hashtable __union_table(1<<20)`,
// so each child allocated and zeroed 8MB of buckets, measured at 2017 extra
// minor faults per run (441527 -> 38176 over 200 fork-server runs, 6.42s ->
// 5.70s).  It is now default-constructed into .bss, with dfsan_init calling
// init() above the fork point.
//
// A relapse is completely silent: the runtime still works, it is just slower per
// child.  So check the property directly -- any new static object in the runtime
// with a nontrivial constructor fails here, and the fix is the same one, an
// explicit init() called from dfsan_init above the fork point.
//
// The one exception is upstream compiler-rt's own sanitizer_common_libcdep.cpp,
// which we vendor rather than own.  It doubles as the proof that this test is
// looking at a binary that really does link the runtime.
//
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: llvm-nm %t.fg > %t.syms
// RUN: python3 -c 'import sys;                                                \
// RUN:   c = [l.split()[-1] for l in open(sys.argv[1])                        \
// RUN:        if "GLOBAL__sub_I" in l];                                       \
// RUN:   print("control:", "runtime-linked" if any("sanitizer_common" in x    \
// RUN:                     for x in c) else "VACUOUS");                       \
// RUN:   print("runtime-ctors:",                                              \
// RUN:         sorted(x for x in c if "sanitizer_common" not in x))'          \
// RUN:   %t.syms | FileCheck %s

// CHECK: control: runtime-linked
// CHECK: runtime-ctors: []

// And the binary the symbols came from has to be one that actually traces, or
// the check above is about a binary nobody would ship.  Note this is the
// exec-per-run path; the fork server is where the cost was, but a table built
// below the fork point still works, so there is nothing here for a run to see.
// RUN: python3 -c 'import sys; sys.stdout.buffer.write(b"SX\x01\x02")' > %t.bin
// RUN: %fgtest %t.fg %t.bin 2>&1 \
// RUN:   | FileCheck --check-prefix=TRACE --implicit-check-not="no events" %s

// TRACE: generate #{{[0-9]+}} output

#include <stdio.h>

int main(int argc, char **argv) {
  unsigned char b[4] = {0};
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  fread(b, 1, sizeof(b), f);
  fclose(f);
  if (b[0] == 'S' && b[1] == 'X') printf("hit\n");
  return 0;
}
