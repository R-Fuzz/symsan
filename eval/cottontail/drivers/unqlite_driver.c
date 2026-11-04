/* Reconstructed driver: compile+run the Jx9 script in argv[1] against an in-memory UnQLite DB. */
#include <stdio.h>
#include <stdlib.h>
#include "unqlite.h"
static int out(const void *p, unsigned int n, void *u) { (void)p; (void)n; (void)u; return UNQLITE_OK; }
int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *buf = malloc(n + 1); n = fread(buf, 1, n, f); buf[n] = 0; fclose(f);
  unqlite *db; unqlite_vm *vm;
  if (unqlite_open(&db, ":mem:", UNQLITE_OPEN_CREATE) != UNQLITE_OK) return 1;
  if (unqlite_compile(db, buf, (int)n, &vm) == UNQLITE_OK) {
    unqlite_vm_config(vm, UNQLITE_VM_CONFIG_OUTPUT, out, 0);
    unqlite_vm_exec(vm); unqlite_vm_release(vm);
  }
  unqlite_close(db); free(buf); return 0;
}
