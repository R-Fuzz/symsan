/* Test target for the Rust binding's undefined-behaviour test.
 *
 * Self-contained -- no tests/lib.h -- like branch.c, so the test can compile it
 * with nothing but a path.  Two things happen to the input, and the test needs
 * both:
 *
 *   - one ordinary branch, whose id is one of AFL++'s edge ids and so resolves
 *     in the branch map;
 *   - one signed division by a value read straight from the input, which the
 *     taint runtime turns into a `ub_division_by_zero` check whose id is *not*
 *     an edge id -- it is an `enum undefined_check_ids` value, below
 *     symsan::AFL_ID_BASE.
 *
 * The branch is deliberately a bare `if` with no `else` and no early return:
 * that shape leaves its true side a numbered block, so a trace that takes the
 * branch false asks the map about a direction the map can answer for.  A body
 * that itself ends in a conditional branch would be pruned as a full dominator
 * (see branch.c, where exactly that happens) and the lookup would miss for a
 * reason that has nothing to do with what this test is about.
 *
 * There is no exit-code oracle here.  What the test wants to know is whether a
 * solution actually provokes the undefined behaviour, and the honest way to ask
 * that is to run the plain build and watch it die: an x86 integer division by
 * zero traps, so the answer is SIGFPE or nothing.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 8

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <file>\n", argv[0]);
    return -1;
  }

  unsigned char buf[INPUT_SIZE];
  memset(buf, 0, sizeof(buf));

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    perror("fopen");
    return -1;
  }
  fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  int32_t a = 0, b = 0;
  memcpy(&a, buf + 0, 4);
  memcpy(&b, buf + 4, 4);

  if (a == 0x11223344) {
    printf("magic\n");
  }

  printf("%d\n", a / b);
  return 0;
}
