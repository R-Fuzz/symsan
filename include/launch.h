#ifndef SYMSAN_LAUNCH_H
#define SYMSAN_LAUNCH_H

#include <stdint.h>
#include <stddef.h>     /* size_t */
#include <sys/types.h>  /* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

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

/// @brief set the solve UB mode for the target binary
int symsan_set_solve_ub(int enable);

/// @brief set the exit on memory error mode for the target binary
int symsan_set_exit_on_memerror(int enable);

/// @brief set the trace file size mode for the target binary
int symsan_set_trace_file_size(int enable);

/// @brief set the force stdin mode for the target binary
int symsan_set_force_stdin(int enable);

/// @brief run the target as a fork server instead of exec'ing it per input
///
/// The target is spawned once, on the first symsan_run(), and thereafter forks
/// a child per input -- which skips execv, dynamic linking and the shadow and
/// union table setup every time.  Requires a target built against a backend
/// that implements one (currently Fastgen); if the handshake does not come
/// back, the launcher falls back to exec'ing per run and this is a no-op.
///
/// Only valid for file input: a stdin or network target still needs its fd
/// wired up per run, which cannot be done from outside a running process.
int symsan_set_forkserver(int enable);

/// @brief size the AFL++-compatible coverage map handed to the target
///
/// The target's edge counters -- present when it was built the two-stage way,
/// see instrumentation/TaintPass.cpp and runtime/dfsan/afl_compat.cpp -- write
/// into a shared segment the launcher owns and passes down as __AFL_SHM_ID.
/// This says how big it has to be; the answer is the target's edge count, which
/// TaintPass records in the `edges=` header of the branch map it writes.
///
/// Optional.  Left unsaid, the map is created at AFL++'s own MAP_SIZE on the
/// first symsan_run(), and a target needing more than that refuses to start
/// with a message naming the size it wanted.  Sizes below that minimum are
/// rounded up, and a request no larger than the current map is a no-op, so this
/// is safe to call repeatedly.
///
/// Must be called before the first symsan_run() when the fork server is in use:
/// the server attaches once, ahead of forking anything, and cannot be moved to
/// a new segment afterwards.  Growing the map after that point returns
/// SYMSAN_INVALID_ARGS rather than quietly leaving the children writing
/// somewhere nobody reads.
///
/// @param edges: bytes of counter space needed, or 0 for the default
/// @return success or error code
int symsan_set_cov_map_size(size_t edges);

/// @brief the coverage map, holding the edge counts of the run just finished
///
/// Zeroed by each symsan_run(), so between a run and the next one this is that
/// run's coverage alone -- real AFL++ counters, including edges reached with
/// untainted conditions, which the backend's own address bookkeeping never saw.
/// Counts are raw, not bucketed; a consumer comparing against a fuzzer's map
/// applies AFL's count classes itself.
///
/// @param size: out, size of the map in bytes; may be NULL
/// @return base of the map, or NULL before the first symsan_run()
uint8_t *symsan_get_cov_map(size_t *size);

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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !SYMSAN_LAUNCH_H */
