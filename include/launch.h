#ifndef SYMSAN_LAUNCH_H
#define SYMSAN_LAUNCH_H

#include <stdint.h>

#define SYMSAN_INVALID_ARGS 1;
#define SYMSAN_NO_MEMORY 2;
#define SYMSAN_MISSING_BIN 3;
#define SYMSAN_MISSING_SHM 4;
#define SYMSAN_MISSING_INPUT 5;
#define SYMSAN_MISSING_ARGS 6;

/// @brief initialize symsan launcher
/// @param symsan_bin: path to symsan binary
/// @param uniontable_size: size of union table
/// @return pointer to the mapped union table
void* symsan_init(const char *symsan_bin, size_t uniontable_size);

/// @brief set the input file for the target binary
/// @param input: "stdin" or "file_path" or "protocol@host:port"
/// @return success or error code
int symsan_set_input(const char *input);

/// @brief set the arguments for the target binary
/// @param argc: number of arguments
/// @param argv: array of arguments
/// @return success or error code
int symsan_set_args(const int argc, char* const argv[]);

/// @brief set the debug mode for the target binary
int symsan_set_debug(int enable);

/// @brief set the bounds check mode for the target binary
int symsan_set_bounds_check(int enable);

/// @brief set the exit on memory error mode for the target binary
int symsan_set_exit_on_memerror(int enable);

/// @brief set the trace file size mode for the target binary
int symsan_set_trace_file_size(int enable);

/// @brief set the force stdin mode for the target binary
int symsan_set_force_stdin(int enable);

/// @brief run the target binary with the input file descriptor
/// @param fd: input file descriptor, only used if input is "stdin"
/// @return < 0 on syscall error, > 0 on setup error, 0 on success
int symsan_run(int fd);

/// @brief read event from target binary, will perform cleanup on timeout and EOF
/// @param buf: buffer to read into
/// @param size: size of buffer
/// @param timeout: timeout in milliseconds, 0 for no timeout
/// @return -1 on error, otherwise number of bytes read
ssize_t symsan_read_event(void *buf, size_t size, unsigned int timeout);

/// @brief terminate target binary
int symsan_terminate();

/// @brief retrieve exit status
int symsan_get_exit_status(int *status);

/// @brief teardown shared men
void symsan_destroy();

#endif /* !SYMSAN_LAUNCH_H */
