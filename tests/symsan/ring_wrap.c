// The event ring's wrap and back-pressure paths, which nothing else reaches.
//
// With the 4MB default a real target never fills the ring and never wraps, so
// both paths would ship unexercised: libpng's worst input is ~29k events at
// ~40 bytes, about a quarter of one lap.  This test forces ring_size=4096 --
// roughly 113 pipe_msgs, a lap every few dozen branches -- against a target
// that emits tens of thousands, so the producer wraps hundreds of times and
// blocks on a full ring for most of the run.  Measured on this target: 580
// blocking waits, so the back-pressure path is not incidental here, it is the
// common case.  The 68-byte memcmp payloads (a 4-byte memcmp_msg plus
// NEEDLE_SIZE of content) are there for the case a stream of one fixed-size
// record cannot make: a record whose length the *target* chose, at a size the
// 36-byte cond stride never lands on, so the two-memcpy split at the wrap point
// happens at offsets a uniform stride would step straight over -- and a record
// that does not fit in free space a cond would have fit in, so the producer
// blocks with the ring part-full rather than only when it is flush.
//
// The assertion is byte-identity of the whole report against the pipe, not
// "it still solves".  That matters because a ring bug is silent: a dropped or
// duplicated record desynchronizes the consumer's byte stream, and what the
// parser then reports is a bad label at some unrelated branch, indistinguishable
// from a target that simply traced something odd.  Only comparing the two
// transports on the same target names it.  PARSE-SUMMARY carries events= and
// the per-site/per-cid histograms carry where, so a diff of the report is a
// diff of the stream in everything that can differ.
//
// Parse-only on purpose, and not only for speed: it makes the consumer the slow
// side by an order of magnitude (an RGD parse per cond, against a memcpy per
// emit), which is what keeps the producer pressed against a full ring instead
// of racing ahead of a consumer that is merely counting.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*16)' > %t.bin
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s

// The two transports, same target, same seed.  SYMSAN_NO_RING=1 is the pipe
// this change replaced; no SYMSAN_RING_SIZE would take the 4MB default and
// prove nothing.
// RUN: env SYMSAN_PARSE_ONLY=1 SYMSAN_NO_RING=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin > %t.pipe.txt
// RUN: env SYMSAN_PARSE_ONLY=1 SYMSAN_RING_SIZE=4096 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin > %t.tiny.txt
// RUN: diff %t.pipe.txt %t.tiny.txt

// A ring that dropped everything would also make the two agree, so pin the
// volume: the counts below must be large enough that 4096 bytes is many laps.
// RUN: FileCheck --check-prefix=CHECK-VOL %s < %t.tiny.txt

// And the default size must reach the same answer by the path that never
// blocks, which is the one every other test in this suite takes.
// RUN: env SYMSAN_PARSE_ONLY=1 TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest %t.fg %t.bin > %t.big.txt
// RUN: diff %t.pipe.txt %t.big.txt

// Five digits of events, i.e. at least 10000 records of ~36 bytes: 87 laps of
// a 4096-byte ring at the very least, and ~320 in practice.  Spelled out
// character by character because FileCheck's own {{ }} delimiters swallow a
// regex repetition brace -- `[0-9]{5,}` inside {{ }} is a "braces not balanced"
// error, not a match.
// The empty= in the middle is the payload records specifically.  Without it the
// test would still pass on a stream of nothing but 36-byte conds, and the
// two-memcpy split of a payload record -- half the reason this file exists --
// would go uncovered with no sign of it.  empty= counts conds that parsed to no
// task, and here that is exactly the NEEDLE_REPS memcmp results: it was 0 before
// the memcmp loop was added and tracks it one for one, so it is the cheapest
// witness that all 64 payloads were emitted and drained.  The fields are matched
// in the order PARSE-SUMMARY prints them.
// CHECK-VOL: PARSE-SUMMARY conds={{[0-9][0-9][0-9][0-9][0-9]+}}
// CHECK-VOL-SAME: empty=64
// CHECK-VOL-SAME: events={{[0-9][0-9][0-9][0-9][0-9]+}}

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"

#define BUF_SIZE 4096

// 64 and not more, which is the ceiling the runtime currently imposes rather
// than a size this test wanted: __dfsw_memcmp passes n as dfsan_union's `size`,
// a byte count into a field __taint_union reads as a bit width, so `size > 64`
// drops the label and a memcmp of 65 bytes traces nothing at all -- not even
// the conds on its result.  See #140; the boundary is measured there.  Until
// that is fixed, 64 is the largest payload record any target can produce, and
// with a 4096-byte ring under back-pressure the free space is routinely below
// that, which is the case this record is here for.
#define NEEDLE_SIZE 64
#define NEEDLE_REPS 64

// Not const, and not a string literal: a memcmp against a constant the
// optimizer can see through gets folded, and then there is no payload record
// to straddle anything.
static char needle[NEEDLE_SIZE];

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char *buf = (unsigned char *)malloc(BUF_SIZE);
  if (!buf) return -1;

  FILE *fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, BUF_SIZE, fp);
  fclose(fp);

  for (int i = 0; i < NEEDLE_SIZE; i++)
    needle[i] = (char)(i & 0x3f);

  // The bulk of the events.  Every one of these comparisons is on a tainted
  // byte, so each is a cond message; the sum over the sweep is what makes the
  // ring lap.  Ten passes rather than one long loop so the trace keeps
  // returning to the same branches under different callstack contexts, which
  // is what a real parser sees.
  uint32_t acc = 0;
  for (int pass = 0; pass < 10; pass++) {
    for (int i = 0; i < BUF_SIZE; i++) {
      if (buf[i] > (unsigned char)(pass * 16))
        acc += buf[i];
      else
        acc ^= buf[i];
    }
  }

  // The payload records, between the passes so they land mid-stream with the
  // ring already part-full rather than at a quiet start.  One side concrete, or
  // the runtime ships no content and there is no payload record at all (see the
  // has_content gate in __taint_trace_cmpfn).
  //
  // Ordered, not `== 0`: clang rewrites an equality-only memcmp into bcmp, and
  // the libc abilist marks bcmp uninstrumented, so the wrapper that emits the
  // payload never runs and the whole point of this record is lost -- silently,
  // as a test that passes on a stream with nothing large in it.
  //
  // A run of them at staggered offsets rather than one: each is two records
  // back to back (the pipe_msg, then sizeof(memcmp_msg) + 64 bytes of content),
  // and 64 of those spread through the trace land the pair at enough different
  // phases of a 4096-byte ring to catch a split copy that only mishandles one
  // alignment.
  for (int rep = 0; rep < NEEDLE_REPS; rep++) {
    int mc = memcmp(buf + rep * 7, needle, NEEDLE_SIZE);
    if (mc > 0) {
      acc += 1;
    } else if (mc < 0) {
      acc += 2;
    }
  }

  for (int pass = 0; pass < 10; pass++) {
    for (int i = 0; i < BUF_SIZE; i++) {
      if (buf[i] < (unsigned char)(200 - pass * 16))
        acc += buf[i] * 3;
      else
        acc -= buf[i];
    }
  }

  printf("acc=%u\n", acc);
  free(buf);
  return 0;
}
