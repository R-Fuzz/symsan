// Dictionary tokens: the comparands a trace saw, handed to a token mutator.
//
// This is the collector in include/tokens.h, driven through afltest's
// --dump-tokens.  It is deliberately not a solving test: nothing here checks
// that a branch flipped.  What it locks in is the *other* half of a trace --
// which concrete byte strings the target wanted to see, including for
// comparisons no solver is asked about.
//
// Three sources, and six things that must NOT become tokens:
//
//   memcmp        the runtime already ships the concrete side verbatim
//   byte chain    single-byte equalities at consecutive offsets, assembled in
//                 trace order.  This is the one an AFL++ LTO autodict cannot
//                 have: `buf[0]=='<' && buf[1]=='?'` puts no string in the
//                 binary, so a pass that reads the binary's constants finds
//                 nothing.  libxml2 spells its whole syntax this way.
//   integer       a wide constant compared against an *image* of input bytes,
//                 in both byte orders -- the constant is in host order and the
//                 file may not be, and printability cannot tell the two apart
//                 (`ntohl(tag)=="IHDR"` needs big, memcpy-then-compare needs
//                 little)
//   arithmetic    the same shape with a computation under it.  A sum, a length,
//                 a buffer position: no byte string in the file can make one of
//                 them equal a constant, and on libxml2 this class was 650 of
//                 845 collected tokens before the rule went in
//   short int     values under 256 are havoc's arithmetic mutator's job
//   one byte      a one-byte token is a byte flip, which havoc does for free
//   scan loop     `while (*p != c) p++` compares one character against every
//                 offset it walks past; the run that produces is not a literal
//   uniform       0xffffffff and 0x00000000 are everywhere and mean nothing
//   cast padding  the high bytes of a 32-bit compare against a 2-byte image
//                 belong to the zero-extension, not to the file
//
// RUN: rm -rf %t.out %t.tokens
// RUN: mkdir -p %t.out
// The input is built to make every compare below run: the chain matches so all
// five of its bytes are traced rather than short-circuited, the memcmp matches,
// and the scan loop finds its '@' after four misses.
// RUN: python3 -c "import sys; b=bytearray(72); b[0:5]=b'<?xml'; b[8:16]=b'MAGICSTR'; b[16:20]=(0xdeadbeef).to_bytes(4,'little'); b[20:24]=(6).to_bytes(4,'little'); b[24:28]=b'....'; b[28]=0x40; b[44:49]=b'abcde'; b[49:52]=b'###'; b[52:56]=b'KEY\\0'; b[56:60]=b'\\xff\\xff\\xff\\xff'; b[60:62]=(0xabcd).to_bytes(2,'little'); b[63]=ord('Z'); b[64:66]=b'XY'; b[66:68]=(3).to_bytes(2,'little'); sys.stdout.buffer.write(bytes(b))" > %t.bin
// RUN: clang -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// KO_DONT_OPTIMIZE=1 is load-bearing: ko-clang's default is -O3, where clang
// merges the byte chain into one word load and inlines the memcmp into another,
// so both arrive as the integer source and the channels this test exists to
// separate become one.  (Which is itself worth knowing -- on an optimized build
// the integer source is doing the byte chain's job.)
// RUN: env KO_DONT_OPTIMIZE=1 KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %afltest \
// RUN:     --dump-tokens %t.tokens %t.fg %t.bin
// RUN: FileCheck --check-prefix=CHECK-TOK --input-file=%t.tokens %s
//
// The tokens are written sorted, so these run in ASCII order, and a CHECK-NOT
// between two CHECKs constrains exactly the gap between them.  The NOTs below
// therefore make the list *exhaustive* rather than merely a subset: a token
// that should have been filtered lands in one of the gaps whatever it is, and
// each gap is spelled out because that is where the corresponding filter's
// output would sort.
//
// Nothing sorts before "<?xml".  Two filters' output would land here: the
// under-256 compare's "\x05\x00\x00\x00", and "\x00\x00\xab\xcd" -- the 16-bit
// image widened to the compare's 32 bits instead of the other way round.
// CHECK-TOK-NOT: token_
//
// The byte chain, assembled from five separate i8 compares:
// CHECK-TOK: token_{{[0-9]+}}="<?xml"
//
// '@' is 0x40, so a "@@@@@" run from the scan loop would land in this gap.
// CHECK-TOK-NOT: token_
//
// The bswapped tag, both orders.  This is the case the image rule has to keep
// while refusing the sum below: the runtime decomposes bswap into Extracts and
// Concats, which move bytes without computing anything.
// CHECK-TOK: token_{{[0-9]+}}="IHDR"
// CHECK-TOK-NOT: token_
//
// The strcmp literal, with the terminator the runtime shipped taken back off.
// "KEY\x00" would sort immediately after this line's match, so the NOT under it
// is what holds that.
// CHECK-TOK: token_{{[0-9]+}}="KEY"
// CHECK-TOK-NOT: token_
//
// The memcmp comparand, shipped whole by the runtime:
// CHECK-TOK: token_{{[0-9]+}}="MAGICSTR"
// CHECK-TOK-NOT: token_
//
// CHECK-TOK: token_{{[0-9]+}}="RDHI"
//
// The two-byte chain, without the word compare that follows it at offset 66.
// CHECK-TOK: token_{{[0-9]+}}="XY"
//
// Two things sort into this gap.  "XY\x03" is the chain with that word compare
// spliced onto it, which is what a single_byte_source that did not check the
// load's width would produce.  "Z" is 0x5a: the lone byte compare at offset 63
// is a run of one, and the size floor is what stops it becoming a token.
// CHECK-TOK-NOT: token_
//
// The literal in front of the second scan loop, kept because the cut is made at
// the scan rather than around the whole run.  "abcde###" and "###" would both
// sort here too, and must not appear.
// CHECK-TOK: token_{{[0-9]+}}="abcde"
//
// The 16-bit image, clamped to the image's width rather than the compare's.
// CHECK-TOK: token_{{[0-9]+}}="\xab\xcd"
//
// Both encodings of 0xcafebabe start with "\xbe" or "\xca", so the sum's tokens
// would land in this gap if the image rule stopped refusing arithmetic.
// CHECK-TOK-NOT: token_
//
// CHECK-TOK: token_{{[0-9]+}}="\xcd\xab"
//
// "\xcd\xab\x00\x00" -- the other half of the unclamped pair -- sorts here.
// CHECK-TOK-NOT: token_
//
// 0xdeadbeef in both orders.  Big-endian first only because "\xde" sorts before
// "\xef"; the point is that both are present.
// CHECK-TOK: token_{{[0-9]+}}="\xde\xad\xbe\xef"
// CHECK-TOK-NOT: token_
// CHECK-TOK: token_{{[0-9]+}}="\xef\xbe\xad\xde"
//
// And nothing after.  Two things would sort into this last gap: the all-ones
// compare, which uniform_bytes drops, and a one-byte token from any of the
// chain's own compares, which the size floor drops before it is interned.
// CHECK-TOK-NOT: token_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2) return 1;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  unsigned char buf[72];
  memset(buf, 0, sizeof(buf));
  if (fread(buf, 1, sizeof(buf), f) != sizeof(buf)) { fclose(f); return 1; }
  fclose(f);

  int hits = 0;

  // A keyword checked one character at a time, the way a hand-written parser
  // reads it.  The input matches, so all five compares are traced; a mismatch
  // would short-circuit and the chain would stop there, which is correct --
  // the target never looked at the rest.
  if (buf[0] == '<' && buf[1] == '?' && buf[2] == 'x' && buf[3] == 'm' &&
      buf[4] == 'l') {
    hits |= 1;
  }

  // The same string as one call, which is what the autodict would already have.
  if (memcmp(buf + 8, "MAGICSTR", 8) == 0) hits |= 2;

  // A 32-bit constant compare.  memcpy rather than a cast so the load is
  // unaligned-safe and the compare is on a value, not a dereference.
  uint32_t v;
  memcpy(&v, buf + 16, 4);
  if (v == 0xdeadbeefu) hits |= 4;

  // Under 256: havoc's arithmetic mutator reaches this without a dictionary.
  uint32_t small;
  memcpy(&small, buf + 20, 4);
  if (small == 5u) hits |= 8;

  // Arithmetic under the comparison.  The constant is wide and the operand is
  // symbolic, so this looks exactly like the tag check below -- but no byte
  // string placed in the file makes a sum equal 0xcafebabe, because the value
  // compared is not an image of the file's bytes.  This is the whole difference
  // between a dictionary and noise: on libxml2 the un-gated version collected
  // 650 size_t comparisons, buffer positions and lengths, none of them
  // matchable.
  uint32_t a, b;
  memcpy(&a, buf + 32, 4);
  memcpy(&b, buf + 36, 4);
  if (a + b == 0xcafebabeu) hits |= 32;

  // The same shape with the bytes only rearranged, which the rule must keep:
  // the file holds "IHDR" and the constant is the number that spells.  bswap is
  // decomposed by the runtime into Extracts and Concats, so it reads as an
  // image rather than as arithmetic.
  uint32_t tag;
  memcpy(&tag, buf + 40, 4);
  if (__builtin_bswap32(tag) == 0x49484452u) hits |= 64;

  // A scan loop.  Every offset it walks past is compared against the same
  // character, so the run it produces is "@@@@@@..." -- a statement about the
  // loop, not about anything the input should contain.
  size_t i = 24;
  while (i < 40 && buf[i] != '@') i++;
  if (i < 40) hits |= 16;

  // The same, but preceded by a literal the parser matched at the offsets just
  // before it, so the scan is only three of the run's eight bytes and no single
  // character has a majority.  This is the shape libxml2 produces -- it left
  // "://%%%%-" and "'''<" in the collected set -- and it is why the filter cuts
  // at three of a character in a row rather than judging the run as a whole:
  // "abcde" survives, "###" does not, and neither does "abcde###".
  if (buf[44] == 'a' && buf[45] == 'b' && buf[46] == 'c' && buf[47] == 'd' &&
      buf[48] == 'e') {
    size_t j = 49;
    while (j < 52 && buf[j] == '#') j++;
    hits |= 128;
  }

  // A NUL-terminated compare.  The runtime ships the literal the way the target
  // wrote it, terminator included, but the terminator belongs to the C string
  // rather than to the file -- splicing it into an XML document would truncate
  // whatever followed.
  if (strcmp((char *)buf + 52, "KEY") == 0) hits |= 256;

  // An all-ones compare.  It is a perfectly good byte image -- four bytes
  // straight off the file -- and still worthless as a token: 0xffffffff, 0 and
  // the 0xaaaa/0xcccc fill patterns turn up in every program.
  uint32_t ones;
  memcpy(&ones, buf + 56, 4);
  if (ones == 0xffffffffu) hits |= 512;

  // A two-byte image compared at 32 bits, because C promotes both sides.  The
  // constant's high half is the zero-extension's, so the token is the low two
  // bytes: a file holding "\x00\x00\xcd\xab" matches nothing.
  uint16_t half;
  memcpy(&half, buf + 60, 2);
  if ((uint32_t)half == 0xabcdu) hits |= 1024;

  // A two-byte chain followed by a *word* compare against a small value at the
  // next offset.  The word is not a character test however small the constant
  // is, and single_byte_source refusing it on the load's width is what keeps
  // the "\x03" out of the chain -- a token mutator handed "XY\x03" would write
  // a byte the file never has to contain.
  if (buf[64] == 'X' && buf[65] == 'Y') hits |= 4096;
  uint16_t pair;
  memcpy(&pair, buf + 66, 2);
  if (pair == 3u) hits |= 8192;

  // A byte compare that is not part of any chain -- the offsets on either side
  // of it are never compared -- so the run it produces is one byte long.  After
  // the pair above rather than before it: offset 63 is one below 64, so putting
  // it first would splice the 'Z' onto the front of the chain.
  if (buf[63] == 'Z') hits |= 2048;

  // CHECK-ORIG: hits=16279
  printf("hits=%d\n", hits);
  return 0;
}
