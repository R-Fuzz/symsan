/* Test target for the throttled case of Session::input_taint().
 *
 * One static branch executed once per input byte, so a small
 * `max_local_branch_counter` throttles all but the first couple of iterations
 * away.  The bytes those iterations read must still come back tainted and
 * open: the dependency is recorded before the throttle, and a branch we
 * declined to *solve* is still a branch whose other direction is unreached.
 *
 * Deliberately self-contained -- no tests/lib.h -- so the test can compile it
 * with nothing but ko-clang and a path.  The trailing INPUT_SIZE - LOOP_BYTES
 * bytes are never read, which is the untainted control group.
 *
 * Exit code is the number of matching bytes, so a caller can tell what the
 * program did without parsing stdout.
 */
#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 16
#define LOOP_BYTES 8

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

  int n = 0;
  for (int i = 0; i < LOOP_BYTES; i++) {
    if (buf[i] == 'Z') {
      n++;
    }
  }

  printf("%d\n", n);
  return n;
}
