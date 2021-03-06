//===-- dfsan_interceptors.cc ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Interceptors for standard library functions.
//===----------------------------------------------------------------------===//

#include <sys/syscall.h>
#include <unistd.h>

#include "dfsan.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_common.h"

using namespace __sanitizer;

namespace {

static bool interceptors_initialized;

void ReleaseShadowMemoryPagesToOS(void *addr, SIZE_T length) {
  uptr beg_shadow_addr = (uptr)__dfsan::shadow_for(addr);
  void *end_addr =
      (void *)((uptr)addr + RoundUpTo(length, GetPageSizeCached()));
  uptr end_shadow_addr = (uptr)__dfsan::shadow_for(end_addr);
  ReleaseMemoryPagesToOS(beg_shadow_addr, end_shadow_addr);
}

}

INTERCEPTOR(void *, mmap, void *addr, SIZE_T length, int prot, int flags,
            int fd, OFF_T offset) {
  void *res = nullptr;
  
  // interceptors_initialized is set to true during preinit_array, when we're
  // single-threaded.  So we don't need to worry about accessing it atomically.
  if (!interceptors_initialized)
    res = (void *)syscall(__NR_mmap, addr, length, prot, flags, fd, offset);
  else
    res = REAL(mmap)(addr, length, prot, flags, fd, offset);

  if (res != (void*)-1)
    ReleaseShadowMemoryPagesToOS(res, length);
  return res;
}

INTERCEPTOR(void *, mmap64, void *addr, SIZE_T length, int prot, int flags,
            int fd, OFF64_T offset) {
  void *res = REAL(mmap64)(addr, length, prot, flags, fd, offset);
  if (res != (void*)-1)
    ReleaseShadowMemoryPagesToOS(res, length);
  return res;
}

INTERCEPTOR(int, munmap, void *addr, SIZE_T length) {
  int res = REAL(munmap)(addr, length);
  if (res != -1) {
    ReleaseShadowMemoryPagesToOS(addr, length);
  }
  return res;
}

namespace __dfsan {
void InitializeInterceptors() {
  CHECK(!interceptors_initialized);

  INTERCEPT_FUNCTION(mmap);
  INTERCEPT_FUNCTION(mmap64);
  INTERCEPT_FUNCTION(munmap);

  interceptors_initialized = true;
}
}  // namespace __dfsan
