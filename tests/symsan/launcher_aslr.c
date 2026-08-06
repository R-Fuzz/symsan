// The launcher spawns traced children with ASLR off.
//
// dfsan_init reserves [UnusedAddr(), AppAddr()) so that no application
// allocation can come back without shadow behind it.  The executable is non-PIE
// and sits above that range for good, but the kernel's mmap base -- where ld.so,
// libc and everything the loader maps go -- is drawn uniform over 16TB, and the
// bottom 16GB of that range fall *below* AppAddr().  So roughly one exec in 2^10
// used to drop the loader inside the region about to be reserved, and MAP_FIXED
// unmapped ld.so out from under the running _dl_init.  That is what "a traced run
// read zero events" was, measured at 3/3000, and it cost a long detour through
// the event transport before anyone looked at the address space.
//
// The runtime now asks with MAP_FIXED_NOREPLACE and re-execs itself with
// ADDR_NO_RANDOMIZE if it loses the draw, so the collision is survivable
// wherever the binary is run from.  child_disable_aslr() in the launcher is the
// other half: every front-end that traces a target goes through launch.c
// (fgtest/afltest directly, driver/aflpp via rgd::ConcolicSession, symsan-fuzz
// via libsymsan_c), so setting the personality between fork() and execv() there
// keeps the runtime's recovery path unexercised on the paths we control -- and
// gives traced runs a reproducible address space for free.
//
// A relapse here is silent: it just restores the 1-in-1024.  Hence this test.
//
// The probe records AT_BASE, the loader's load address, which *is* the mmap
// base.  Both launcher spawn sites are covered: one input takes the exec-per-run
// path, two inputs make fgtest ask for a fork server.
//
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: rm -f %t.direct %t.launched
// RUN: python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(16)))' > %t.bin

// The control.  Run outside the launcher the base has to move, otherwise this
// test would pass just as well with child_disable_aslr() deleted.
// RUN: env PROBE_OUT=%t.direct %t.fg %t.bin
// RUN: env PROBE_OUT=%t.direct %t.fg %t.bin
// RUN: env PROBE_OUT=%t.direct %t.fg %t.bin
// RUN: env PROBE_OUT=%t.direct %t.fg %t.bin

// RUN: env PROBE_OUT=%t.launched %fgtest %t.fg %t.bin
// RUN: env PROBE_OUT=%t.launched %fgtest %t.fg %t.bin %t.bin

// RUN: python3 -c 'import sys;                                                 \
// RUN:   d = set(open(sys.argv[1]));                                           \
// RUN:   l = [int(x, 16) for x in open(sys.argv[2])];                          \
// RUN:   on = open("/proc/sys/kernel/randomize_va_space").read().strip() != "0"; \
// RUN:   print("control:", "aslr-observed" if len(d) > 1 else                  \
// RUN:                     ("system-aslr-off" if not on else "VACUOUS"));      \
// RUN:   print("launched:", "pinned" if len(set(l)) == 1 else "moved");        \
// RUN:   print("above-appaddr:", all(b > 0x700000040000 for b in l))'          \
// RUN:   %t.direct %t.launched | FileCheck %s

// CHECK: control: {{aslr-observed|system-aslr-off}}
// CHECK: launched: pinned
// CHECK: above-appaddr: True

#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>

int main(int argc, char **argv) {
  unsigned char buf[16] = {0};
  FILE *in = fopen(argv[1], "rb");
  if (!in) return 1;
  size_t n = fread(buf, 1, sizeof(buf), in);
  fclose(in);

  // One real traced condition, so this is an ordinary target rather than a
  // no-event special case.
  if (n >= 2 && buf[0] == 'S' && buf[1] == 'X') printf("unreachable\n");

  FILE *out = fopen(getenv("PROBE_OUT"), "a");
  if (!out) return 1;
  fprintf(out, "%lx\n", getauxval(AT_BASE));
  fclose(out);
  return 0;
}
