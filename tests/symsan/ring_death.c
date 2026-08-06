// The event channel's death paths.
//
// Everything that can end a run used to be a file-descriptor event, and a file
// descriptor reports a dead peer whether or not the peer meant to say anything.
// With the ring the consumer sleeps on a word in shared memory instead, and a
// dead process cannot write to a word -- so each of those has to be arranged
// for by hand, and anything not arranged for is an indefinite hang rather than
// an error.  Nothing else in this suite reaches them: every other test has a
// target that runs to completion with both ends alive.
//
// This target emits a few thousand conditions and then stops without exiting,
// which is what puts the consumer in the blocked state all three cases are
// about.  The pause is a sleep loop rather than a single long sleep so that a
// SIGKILL lands promptly, and the branches ahead of it are driven by the input
// so that they are real traced events rather than something the compiler folds.
//
// The cases and their expectations live in driver/deathtest.c; each prints
// PASS.  Run one per RUN line so a hang names which one.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)))' > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s

// The traced child stops emitting and never exits: the caller's timeout is the
// only thing left to end the wait.
// RUN: env TAINT_OPTIONS="output_dir=%t.out" %deathtest child %t.fg %t.bin | FileCheck %s --check-prefix=CHILD
// CHILD: PASS child

// The fork server is killed under a consumer blocked with no timeout at all.
// RUN: env TAINT_OPTIONS="output_dir=%t.out" %deathtest server %t.fg %t.bin | FileCheck %s --check-prefix=SERVER
// SERVER: PASS server

// The consumer stops reading with a ring too small to hold the run, so the
// producer blocks on a full ring with nobody draining it.  4096 is the smallest
// the launcher accepts, ~113 events, which this target overruns immediately.
// RUN: env SYMSAN_RING_SIZE=4096 TAINT_OPTIONS="output_dir=%t.out" %deathtest stuck %t.fg %t.bin | FileCheck %s --check-prefix=STUCK
// STUCK: PASS stuck

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) return 1;

  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;

  unsigned char buf[256];
  size_t n = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  if (n == 0) return 1;

  // Enough conditions to fill a 4096-byte ring many times over and to still be
  // a few thousand events on the 4MB default, so the consumer has something to
  // drain before it blocks.
  unsigned long acc = 0;
  for (int round = 0; round < 32; round++) {
    for (size_t i = 0; i < n; i++) {
      if (buf[i] > (unsigned char)round) acc += buf[i];
      if ((buf[i] & 0xf) == round % 16) acc ^= i;
    }
  }

  // Consume acc so nothing above is dead code.
  if (acc == 0xdeadbeef) printf("unreachable\n");

  // Stop talking without exiting.  A pipe would be at EOF here; the ring is
  // simply quiet, which is the whole point.  Bounded so a failing run does not
  // leave a process behind: every case kills this long before it elapses.
  for (int i = 0; i < 120; i++) {
    sleep(1);
  }
  return 0;
}
