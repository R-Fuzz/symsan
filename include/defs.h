#ifndef _HAVE_DEFS_H
#define _HAVE_DEFS_H

#ifdef DEBUG_INFO
// #define DEBUG_PRINTF printf
#define DEBUG_PRINTF(...)                                                      \
  do {                                                                         \
    printf(__VA_ARGS__);                                                       \
  } while (0)
#else
#define DEBUG_PRINTF(...)                                                      \
  do {                                                                         \
  } while (0)
#endif

#ifndef MIN
#define MIN(_a, _b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

#ifndef RRR
#define RRR(x) (random() % (x))
#endif

#include <stdint.h>
#include <stdlib.h>

typedef uint32_t dfsan_label;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#ifdef __x86_64__
typedef unsigned long long u64;
typedef long long s64;
#else
typedef uint64_t u64;
typedef int64_t s64;
#endif
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;

#endif /* ! _HAVE_DEFS_H */
