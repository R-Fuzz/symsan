// Byte-chain tokens through a case-fold mask, the way sqlite keywordCode
// spells `CREATE`: `(z[j] & ~0x20) == zKW[j]`.
//
// include/tokens.h used to treat any And/Or as arithmetic and drop the
// compare.  That is the right rule for `pos + 4 == len`, and the wrong one
// for a mask that only chooses a case: the file still holds the character,
// CmpLog's extras keep the keyword, and without this peel we never did.
//
// The add (`buf[i] + 1 == 'X'`) is the control.  Same shape -- one symbolic
// byte, one constant -- and it must stay out: no byte in the file equals that
// constant, because the value compared is not the file's byte.
//
// RUN: rm -rf %t.out %t.tokens
// RUN: mkdir -p %t.out
// RUN: python3 -c "import sys; sys.stdout.buffer.write(b'create..ab')" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest \
// RUN:     --dump-tokens %t.tokens %t.fg %t.bin
// RUN: FileCheck --check-prefix=CHECK-TOK --input-file=%t.tokens %s
//
// Constant run first (uppercase, as keywordCode stores it), then the file
// slice the walk actually read -- CmpLog's extras are the input n-gram.
// CHECK-TOK: token_{{[0-9]+}}="CREATE"
// CHECK-TOK: token_{{[0-9]+}}="create"
//
// "+" would sort here if the add leaked.  So would "X" from the same compare
// treated as a one-byte run -- the size floor already drops that, but the
// image rule must not let the add through as a wider token either.
// CHECK-TOK-NOT: token_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2) return 1;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  unsigned char buf[10];
  memset(buf, 0, sizeof(buf));
  if (fread(buf, 1, sizeof(buf), f) != sizeof(buf)) {
    fclose(f);
    return 1;
  }
  fclose(f);

  int hits = 0;

  // sqlite keywordCode: hash already matched, then a case-folded walk.
  if ((buf[0] & ~0x20) == 'C' && (buf[1] & ~0x20) == 'R' &&
      (buf[2] & ~0x20) == 'E' && (buf[3] & ~0x20) == 'A' &&
      (buf[4] & ~0x20) == 'T' && (buf[5] & ~0x20) == 'E') {
    hits |= 1;
  }

  // Arithmetic under the compare: must not become a token.
  if ((unsigned)buf[8] + 1u == (unsigned)'X') hits |= 2;

  // CHECK-ORIG: hits=1
  printf("hits=%d\n", hits);
  return 0;
}
