// tolower() into a bounded strncmp, over a buffer with an unwritten tail.
//
// work[] is deliberately larger than the bytes we fill, so its tail is alloca
// shadow that was never written: kInitializingLabel.  strlen() then runs into
// that tail -- work[32] is the first unwritten byte and there is a terminator
// at work[63], so the walk crosses the marker whichever of the two it stops on
// -- and __dfsw_strncmp used to size its label lookup with exactly that strlen.
// __taint_union_load handed the marker straight back, __dfsw_strncmp passed it
// to dfsan_get_label_info(), and dfsan_check_label() reported
// "FATAL: Taint: out of labels" and Die()d, losing the trace at this line and
// everything after it.  This is what kept the fuzzer-challenges test-transform
// target pinned at offset 24.
//
// The comparison is 5 bytes, so the label describing it is now 5 bytes too, and
// nothing reads past what strncmp itself would look at.
//
// isupper() is a __ctype_b_loc table load, which is concrete to us, so the
// solution has to stay uppercase on its own -- Or(x, 0x20) == 'a' admits both
// 'A' and 'a', and picking the lowercase one would fail the gate on the next
// run.  That the generated input prints Good is what pins that down.
//
// KO_DONT_OPTIMIZE=1 is required, not cosmetic: ko-clang otherwise raises the
// optimization level to -O3, which defines __OPTIMIZE__, and glibc's ctype.h
// then expands tolower() to (*__ctype_tolower_loc())[c] -- a constant-table
// load at a symbolic index, which is a different (unsupported) thing entirely
// and never reaches the wrapper this test is about.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'Z'*32)" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 KO_DONT_OPTIMIZE=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[32];
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  if (n != sizeof(buf)) return -1;

  // work[32..62] is never written: that is the uninitialized tail strlen() used
  // to walk into.  The last byte is terminated so strlen() stays in bounds.
  unsigned char work[64];
  memcpy(work, buf, sizeof(buf));
  work[sizeof(work) - 1] = 0;

  for (int i = 0; i < 5; i++) {
    if (!isupper(work[i])) {
      printf("Bad case\n");
      return 0;
    }
    work[i] = tolower(work[i]);
  }

  if (strncmp((char *)work, "abcde", 5) == 0) {
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  return 0;
}
