#ifndef MY_HASH_H
#define MY_HASH_H

#include <stdint.h>

// Rounds up an integer to the next power of two.
static inline int roundUpToPowerOfTwo(int x) {
    if (x < 1) {
        return 1;
    }
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x++;
    return x;
}

// Primary hash function.
static inline u32 hash1(u32 key, int capacity) {
    return key & (capacity - 1);
}

// Secondary hash function for double hashing.
static inline u32 hash2(u32 key, int capacity) {
    u32 h = ((key * 31 + 1) & (capacity - 1));
    if (h == 0) {
        h = 1;
    }
    if ((h & 1) == 0) {
        h ^= 1;
    }
    return h;
}

typedef enum {
    SLOTEMPTY,
    SLOTUSED,
    SLOTDELETED
} SlotState;

#endif // MY_HASH_H
