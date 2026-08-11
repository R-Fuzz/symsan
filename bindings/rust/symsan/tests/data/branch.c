/* Test target for the Rust binding's integration test.
 *
 * Deliberately self-contained -- no tests/lib.h -- so the test can compile it
 * with nothing but ko-clang and a path.  Two nested magic-value checks, which
 * is enough to exercise both the i2s solver (the equality on `x` is a direct
 * input-to-state match) and a task that only becomes reachable once the first
 * one is solved.
 *
 * Exit code doubles as the oracle so the test does not have to parse stdout:
 *   0  neither check passed
 *   1  the first check passed
 *   2  both passed
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 16

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

  uint32_t x = 0, y = 0;
  memcpy(&x, buf + 0, 4);
  memcpy(&y, buf + 8, 4);

  if (x == 0xdeadbeefu) {
    if (y == 0x12345678u) {
      printf("Good\n");
      return 2;
    }
    printf("Halfway\n");
    return 1;
  }

  printf("Bad\n");
  return 0;
}
