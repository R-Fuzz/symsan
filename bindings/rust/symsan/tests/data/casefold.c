// sqlite keywordCode's walk: the keyword is compared one case-folded byte at a
// time, `(z[j] & ~0x20) == zKW[j]`.  On "create..." every compare is true, so a
// trace sees the whole constant run "CREATE" against the file's "create" --
// one apply-at-site smash -- whether or not any branch is still new.
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2) return 1;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  unsigned char buf[10];
  memset(buf, 0, sizeof(buf));
  size_t n = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  if (n != sizeof(buf)) return 1;

  if ((buf[0] & ~0x20) == 'C' && (buf[1] & ~0x20) == 'R' &&
      (buf[2] & ~0x20) == 'E' && (buf[3] & ~0x20) == 'A' &&
      (buf[4] & ~0x20) == 'T' && (buf[5] & ~0x20) == 'E') {
    return 2;
  }
  return 0;
}
