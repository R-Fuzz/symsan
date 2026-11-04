/* Reconstructed driver: parse the JSON file in argv[1] with jansson, re-serialize it. */
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
int main(int argc, char **argv) {
  if (argc < 2) return 1;
  json_error_t e; json_t *j = json_load_file(argv[1], JSON_DECODE_ANY, &e);
  if (!j) return 1;
  char *s = json_dumps(j, JSON_INDENT(2) | JSON_SORT_KEYS); if (s) { puts(s); free(s); }
  json_decref(j); return 0;
}
