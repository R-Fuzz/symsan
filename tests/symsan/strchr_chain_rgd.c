// Chained string parsing on the RGD path: find a delimiter, then search what
// follows it.  That is the normal shape of a parser for a string input format,
// and it is the shape that needs a haystack which is a SLICE of another string
// rather than a string of its own -- `strchr(t1, ';')` searches
// SubStr(content, StrRChr(content, ':')), whose extent is decided by a search.
//
// The seed already contains the colon, so ROUND ONE is the second-level branch
// and one round is enough.  strchr_chain.c and strchr_mixed_chain.c drive the
// same two shapes through fgtest over two rounds; this one is here because the
// RGD path (parsers/rgd-parser.cpp -> i2s) reaches them by a different route
// and used to get them wrong rather than decline:
//
//  * The slice has to flatten at all.  Without that the whole constraint is
//    undecodable and i2s declines -- a miss, but a quiet and honest one.
//  * The plant has to be willing to MOVE.  The cheapest place to write the
//    semicolon is over the colon, which deletes the slice it is being written
//    into; the answer then reads back as "no colon" and satisfies neither
//    branch.  The verify re-flattens from the AST, which is what catches it,
//    and the retry is what turns the catch into an answer.
//
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b':' + b'A'*8)" > %t.bin
// RUN: clang -O0 -fno-builtin -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -O0 -fno-builtin -o %t.fg %s
// RUN: rm -rf %t.rgd.out
// RUN: mkdir -p %t.rgd.out
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.rgd.out" %afltest %t.fg %t.bin
// RUN: %t.uninstrumented %t.rgd.out/id-0-0-1 | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  char buf[256] = {0};
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    fprintf(stderr, "Failed to open\n");
    return -1;
  }
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  buf[n] = '\0';

  char *t1 = strrchr(buf, ':');
  if (t1) {
    char *t2 = strchr(t1, ';');
    if (t2) {
      // CHECK-GEN: semicolon after colon
      printf("semicolon after colon (colon at %ld, semicolon at %ld)\n",
             (long)(t1 - buf), (long)(t2 - buf));
    } else {
      // CHECK-ORIG: colon, no semicolon
      printf("colon, no semicolon\n");
    }
  } else {
    printf("no colon\n");
  }
  return 0;
}
