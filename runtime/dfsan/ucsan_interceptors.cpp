//===-- ucsan_interceptors.cpp - UCSan alone: page-map interceptors -------===//
//
// UCSan's page map (ucsan.cpp map_state) learns of the program's mappings
// from mmap, munmap and mprotect.  The combined build has dfsan's
// interceptors (dfsan_interceptors.cpp), which call the __ucsan_note_* hooks;
// UCSan alone has these.  (No <sys/mman.h> here: its declarations conflict
// with the interceptors', as in dfsan_interceptors.cpp.)
//
//===----------------------------------------------------------------------===//

#ifndef USE_UCSAN_CUSTOM

#include "interception/interception.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_posix.h"

using namespace __sanitizer;

extern "C" void __ucsan_note_mmap(void *addr, uptr len, int prot, int flags);
extern "C" void __ucsan_note_munmap(void *addr, uptr len);
extern "C" void __ucsan_note_mprotect(void *addr, uptr len, int prot);

static void *const kMapFailed = (void *)-1;

// Before __ucsan_install_map_interceptors (ucsan_init), a call goes to the
// syscall.
static bool installed;

static void *internal_mmap_or_failed(void *addr, SIZE_T length, int prot,
                                     int flags, int fd, OFF64_T offset) {
  uptr res = internal_mmap(addr, length, prot, flags, fd, offset);
  return internal_iserror(res) ? kMapFailed : (void *)res;
}

INTERCEPTOR(void *, mmap, void *addr, SIZE_T length, int prot, int flags,
            int fd, OFF_T offset) {
  void *res = installed
                  ? REAL(mmap)(addr, length, prot, flags, fd, offset)
                  : internal_mmap_or_failed(addr, length, prot, flags, fd, offset);
  if (res != kMapFailed)
    __ucsan_note_mmap(res, length, prot, flags);
  return res;
}

INTERCEPTOR(void *, mmap64, void *addr, SIZE_T length, int prot, int flags,
            int fd, OFF64_T offset) {
  void *res = installed
                  ? REAL(mmap64)(addr, length, prot, flags, fd, offset)
                  : internal_mmap_or_failed(addr, length, prot, flags, fd, offset);
  if (res != kMapFailed)
    __ucsan_note_mmap(res, length, prot, flags);
  return res;
}

INTERCEPTOR(int, munmap, void *addr, SIZE_T length) {
  int res = installed
                ? REAL(munmap)(addr, length)
                : (internal_iserror(internal_munmap(addr, length)) ? -1 : 0);
  if (res == 0)
    __ucsan_note_munmap(addr, length);
  return res;
}

INTERCEPTOR(int, mprotect, void *addr, SIZE_T length, int prot) {
  int res = installed
                ? REAL(mprotect)(addr, length, prot)
                : (internal_iserror(internal_mprotect(addr, length, prot)) ? -1
                                                                           : 0);
  if (res == 0)
    __ucsan_note_mprotect(addr, length, prot);
  return res;
}

extern "C" void __ucsan_install_map_interceptors() {
  INTERCEPT_FUNCTION(mmap);
  INTERCEPT_FUNCTION(mmap64);
  INTERCEPT_FUNCTION(munmap);
  INTERCEPT_FUNCTION(mprotect);
  installed = true;
}

#endif  // USE_UCSAN_CUSTOM
