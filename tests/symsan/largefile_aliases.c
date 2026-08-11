// A target built the way autoconf's AC_SYS_LARGEFILE builds almost everything
// -- libxml2, libsndfile, curl -- never calls `stat`, `open`, `lseek` or their
// siblings: glibc redirects the declarations and the IR calls `stat64`,
// `open64`, `lseek64`.  Each missing alias in done_abilist.txt fails silently,
// and in two different ways:
//
//   * a stat-like function leaves its output buffer's shadow at the
//     uninitialized-stack poison, so the caller's first branch on st_mode hits
//     kInitializingLabel and __taint_trace_cond Die()s -- the trace ends at the
//     target's first stat, before a byte of input is parsed;
//   * an open-like function never registers the input as the taint source, so
//     the trace runs to completion over a program with no symbolic bytes.
//
// Both are covered here: the stat/lstat/fstat/fstatat/getrlimit branches make
// the run die if a shadow was left poisoned, and the solve at the end needs
// both open64 and openat64 to have registered their fd for the four bytes to be
// symbolic at all.  (freopen64 and mmap64 are in the same class but cannot be
// distinguished by a branch, so they are not exercised here.)

// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c'print("AAAA")' > %t.bin
// RUN: clang -D_FILE_OFFSET_BITS=64 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -D_FILE_OFFSET_BITS=64 -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s
// RUN: env KO_USE_Z3=1 %ko-clang -D_FILE_OFFSET_BITS=64 -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: %t.uninstrumented %t.out/id-0-0-0 | FileCheck --check-prefix=CHECK-GEN %s

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  // stat64 / lstat64 / fstatat64: the buffer is a fresh stack object, so its
  // shadow is poison until a wrapper clears it.  This is xmlCheckFilename's
  // shape, the branch xmllint used to die on.
  struct stat st;
  if (stat(argv[1], &st) != 0 || !S_ISREG(st.st_mode)) {
    fprintf(stderr, "not a regular file\n");
    return -1;
  }
  if (lstat(argv[1], &st) == 0 && S_ISLNK(st.st_mode)) {
    fprintf(stderr, "symlink\n");
    return -1;
  }
  if (fstatat(AT_FDCWD, argv[1], &st, 0) != 0 || !S_ISREG(st.st_mode)) {
    fprintf(stderr, "fstatat disagrees\n");
    return -1;
  }

  // getrlimit64, same class, same poison.
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur == 0) {
    fprintf(stderr, "no descriptors\n");
    return -1;
  }

  char buf[4];

  // open64 has to register fd1 as the taint source, or bytes 0-1 stay concrete.
  int fd1 = open(argv[1], O_RDONLY);
  if (fd1 < 0 || read(fd1, buf, 2) != 2) {
    fprintf(stderr, "Failed to read\n");
    return -1;
  }

  // fstat64, on a descriptor this time.
  struct stat st2;
  if (fstat(fd1, &st2) != 0 || !S_ISREG(st2.st_mode)) {
    fprintf(stderr, "fstat disagrees\n");
    return -1;
  }
  close(fd1);

  // openat64 has to register fd2, or bytes 2-3 stay concrete.
  int fd2 = openat(AT_FDCWD, argv[1], O_RDONLY);
  if (fd2 < 0 || lseek(fd2, 2, SEEK_SET) != 2 || read(fd2, buf + 2, 2) != 2) {
    fprintf(stderr, "Failed to read\n");
    return -1;
  }
  close(fd2);

  uint32_t x;
  memcpy(&x, buf, sizeof(x));

  if (x == 0x44414548) { // "HEAD"
    // CHECK-GEN: Good
    printf("Good\n");
  } else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }

  return 0;
}
