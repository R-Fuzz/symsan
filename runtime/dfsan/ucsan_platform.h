//===-- ucsan_platform.h - UCSan Platform Definitions ----------*- C++ -*-===//
//
// UCSan shadow memory and platform-specific definitions (x86_64 only).
//
// UCSan uses 2-byte (16-bit) labels for pointer/object tracking.
// This is separate from SymSan/DFSan which uses 4-byte labels.
//
// Shadow computation:
//   ucsan_shadow = ((ptr & ShadowMask) << 1) + kShadowBase
//
// Layout: shadow first, then union table (no hash table needed).
//
//===----------------------------------------------------------------------===//

#ifndef UCSAN_PLATFORM_H
#define UCSAN_PLATFORM_H

#include "defs.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using __sanitizer::uptr;

namespace __ucsan {

//===----------------------------------------------------------------------===//
// UCSan Label Type (16-bit)
//===----------------------------------------------------------------------===//

typedef u16 ucsan_label;

#define UCSAN_LABEL_MAX 0xFFFF
#define UCSAN_CONST_LABEL 0
#define UCSAN_CONST_OFFSET 1

//===----------------------------------------------------------------------===//
// Memory Layout for UCSan on Linux/x86_64
//===----------------------------------------------------------------------===//
//
// SymSan/DFSan layout (unchanged):
//   Shadow:     0x000000010000 (4-byte labels)
//   HashTable:  0x400000000000
//   UnionTable: 0x400100000000
//
// UCSan layout (separate, 2-byte labels):
//   Shadow:     0x480000000000 (2TB, ends at 0x680000000000)
//   UnionTable: 0x680000000000
//
// App:         0x700000040000 - 0x800000000000
//

static const uptr kShadowBase = 0x480000000000ULL;
static const uptr kUnionTableAddr = 0x680000000000ULL;
static const uptr kAppAddr = 0x700000040000ULL;
static const uptr kAppBaseAddr = 0x700000000000ULL;
static const uptr kShadowMask = ~0x700000000000ULL;

// With 16-bit labels, max 65536 labels
// Each label_info is 24 bytes, so max size = 65536 * 24 = 1.5MB
// Allocate 4MB for safety
static const uptr kUnionTableSize = 0x400000ULL;

//===----------------------------------------------------------------------===//
// Accessors
//===----------------------------------------------------------------------===//

inline uptr ShadowBase() { return kShadowBase; }
inline uptr UnionTableAddr() { return kUnionTableAddr; }
inline uptr AppAddr() { return kAppAddr; }
inline uptr AppBaseAddr() { return kAppBaseAddr; }
inline uptr ShadowMask() { return kShadowMask; }
inline uptr UnusedAddr() { return kUnionTableAddr + kUnionTableSize; }

//===----------------------------------------------------------------------===//
// Shadow Memory Access (2-byte labels, shift by 1)
//===----------------------------------------------------------------------===//

// ucsan_shadow = ((ptr & ShadowMask) << 1) + ShadowBase
inline ucsan_label* ucsan_shadow_for(void *ptr) {
  return (ucsan_label*)(((((uptr)ptr) & kShadowMask) << 1) + kShadowBase);
}

inline ucsan_label* ucsan_shadow_for(const void *ptr) {
  return ucsan_shadow_for(const_cast<void*>(ptr));
}

inline void* ucsan_app_for(const ucsan_label *l) {
  uptr shadow_offset = ((uptr)l) - kShadowBase;
  return (void*)((shadow_offset >> 1) | kAppBaseAddr);
}

}  // namespace __ucsan

#endif  // UCSAN_PLATFORM_H
