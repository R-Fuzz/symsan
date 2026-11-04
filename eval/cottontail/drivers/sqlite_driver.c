/* Reconstructed Cottontail-style file driver: execute the SQL in argv[1] on an in-memory DB. */
#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"
int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *buf = malloc(n + 1); n = fread(buf, 1, n, f); buf[n] = 0; fclose(f);
  sqlite3 *db; if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
  char *err = 0; sqlite3_exec(db, buf, 0, 0, &err); if (err) sqlite3_free(err);
  sqlite3_close(db); free(buf); return 0;
}
