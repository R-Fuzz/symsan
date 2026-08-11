/* Test target for the Rust binding's lookup-table test.
 *
 * Deliberately self-contained -- no tests/lib.h -- so the test can compile it
 * with nothing but ko-clang and a path.
 *
 * `hex[]` is a static global, so without the tlookup op the loaded byte carries
 * label 0, `tmp` is fully concrete, and __dfsw_strncmp takes its "both operands
 * concrete" early return: the session never learns the check exists.  Labelling
 * the load makes `tmp` symbolic and the strncmp an ordinary memcmp constraint,
 * which i2s inverts by scanning the table.  This is the shape that stalls AFL's
 * "test-transform" at offset 30, minimised.
 *
 * Exit code doubles as the oracle so the test does not have to parse stdout:
 *   0  the hex encoding did not match
 *   1  it did
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 8

static uint8_t hex[16] = {'0','1','2','3','4','5','6','7',
                          '8','9','a','b','c','d','e','f'};

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <file>\n", argv[0]);
    return -1;
  }

  uint8_t buf[INPUT_SIZE];
  uint8_t tmp[INPUT_SIZE * 2 + 1];
  memset(buf, 0, sizeof(buf));

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    perror("fopen");
    return -1;
  }
  fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  for (int i = 0; i < INPUT_SIZE; i++) {
    tmp[i << 1]       = hex[buf[i] >> 4];
    tmp[(i << 1) + 1] = hex[buf[i] % 16];
  }
  tmp[INPUT_SIZE * 2] = 0;

  /* the only input satisfying this is "ABCDEFGH" */
  if (strncmp((char *)tmp, "4142434445464748", INPUT_SIZE * 2) == 0) {
    printf("Good\n");
    return 1;
  }

  printf("Bad\n");
  return 0;
}
