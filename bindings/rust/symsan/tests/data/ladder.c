/* Test target for the solver-ladder policy tests.
 *
 * Four independent magic-value checks on disjoint offsets, none of them nested
 * inside another, so one trace produces four tasks that all reach the solver.
 * Every check is a 32-bit equality against a constant, which is precisely what
 * the i2s rung answers -- so the first rung SATs all four and what the second
 * rung does is a question of policy rather than of capability.
 *
 * Not `taint_loop.c`, which would be the obvious choice for "several tasks out
 * of one trace": its eight comparisons are one static branch in a loop, and
 * without the LTO pipeline the byte loads merge into a single wide one and the
 * trace carries no comparisons at all.  Independent branches are what these
 * tests need anyway -- a loop branch's tasks are not independent.
 *
 * Deliberately self-contained -- no tests/lib.h -- so the test can compile it
 * with nothing but ko-clang and a path.
 *
 * Exit code is the number of checks that passed.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 32

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

  uint32_t a = 0, b = 0, c = 0, d = 0;
  memcpy(&a, buf + 0, 4);
  memcpy(&b, buf + 8, 4);
  memcpy(&c, buf + 16, 4);
  memcpy(&d, buf + 24, 4);

  /* The printf in each arm is load-bearing: with a bare `n++` the four
   * comparisons are if-converted into zext-and-add and the trace carries no
   * branches at all.  A call cannot be speculated, so these stay branches. */
  int n = 0;
  if (a == 0xdeadbeefu) { printf("a\n"); n++; }
  if (b == 0x12345678u) { printf("b\n"); n++; }
  if (c == 0xcafebabeu) { printf("c\n"); n++; }
  if (d == 0x0badf00du) { printf("d\n"); n++; }

  printf("%d\n", n);
  return n;
}
