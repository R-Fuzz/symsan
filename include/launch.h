#ifndef SYMSAN_LAUNCH_H
#define SYMSAN_LAUNCH_H

#include "defs.h"

#define SYMSAN_INVALID_ARGS 1;
#define SYMSAN_NO_MEMORY 2;
#define SYMSAN_MISSING_BIN 3;
#define SYMSAN_MISSING_SHM 4;
#define SYMSAN_MISSING_INPUT 5;
#define SYMSAN_MISSING_ARGS 6;

void* symsan_init(const char *symsan_bin, size_t uniontable_size); // set target binary
int symsan_set_input(const char *input); // set input file, could be stdin or network
int symsan_set_args(const int argc, char* const argv[]); // set args
int symsan_set_debug(int enable);
int symsan_set_bounds_check(int enable);
int symsan_run(int fd); // run target binary with input fd
ssize_t symsan_read_event(void *buf, size_t size, unsigned int timeout); // read event from target binary
void symsan_destroy();

#endif /* !SYMSAN_LAUNCH_H */