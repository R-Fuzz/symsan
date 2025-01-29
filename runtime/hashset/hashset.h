#ifndef MY_HASHSET_H
#define MY_HASHSET_H

#include "defs.h"

class HashSet {
private:
    enum SlotState {
        SLOTEMPTY,
        SLOTUSED,
        SLOTDELETED
    };

    u32* keys;
    SlotState* states;
    int capacity;
    int size;
    float loadFactorThreshold;

    u32 hash1(u32 key) const {
        return key & (capacity - 1);
    }

    u32 hash2(uint32_t key) const {
        u32 h = ((key * 31 + 1) & (capacity - 1));
        if (h == 0) {
            h = 1;
        }
        if ((h & 1) == 0) {
            h ^= 1;
        }
        return h;
    }

    void checkLoadFactorAndRehash();
    void rehash(int newCapacity);

public:
    HashSet(int initialCapacity = 8, float loadFactor = 0.75f);
    ~HashSet();

    bool insert(u32 key);
    int getSize() const;
    bool contains(u32 key) const;
    bool remove(u32 key);
};

#endif // MY_HASHSET_H

// --------------------------------------------------------------------------
// Example usage:
// 
// #include <cstdio>

// int main() {
//     HashSet set(8); // capacity=8, loadFactor=0.75
//     set.insert(10);
//     set.insert(20);
//     set.insert(30);
// 
//     if (set.contains(20)) {
//         printf("20 exists.\n");
//     }
// 
//     set.remove(10);
//     if (!set.contains(10)) {
//         printf("10 removed.\n");
//     }
// 
//     return 0;
// }
// --------------------------------------------------------------------------