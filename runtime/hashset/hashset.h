#ifndef MY_HASHSET_H
#define MY_HASHSET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "defs.h"
#include "hash.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    u32* keys;
    SlotState* states;
    int capacity;
    int size;
    float loadFactorThreshold;
} HashSet;

// Creates a new hash set with a given initial capacity.
// The capacity is rounded up to the nearest power of two.
HashSet* hashset_create(int initialCapacity);

// Frees all memory associated with the hash set.
void hashset_free(HashSet* set);

// Inserts a key into the hash set.
// Returns true if the key was inserted, or false if it was already present.
bool hashset_insert(HashSet* set, u32 key);

// Returns true if the key is in the hash set, false otherwise.
bool hashset_contains(const HashSet* set, u32 key);

// Removes a key from the hash set.
// Returns true if the key was removed, or false if the key was not found.
bool hashset_remove(HashSet* set, u32 key);

// Returns the number of elements in the hash set.
int hashset_get_size(const HashSet* set);

#ifdef __cplusplus
}
#endif

#endif // MY_HASHSET_H

// --------------------------------------------------------------------------
/**
// Example usage:

#include <stdio.h>
#include "hashset.h"

int main(void) {
    HashSet* set = hashset_create(8);
    if (!set) {
        return 1; // Allocation failed
    }
    
    hashset_insert(set, 10);
    hashset_insert(set, 20);
    hashset_insert(set, 30);

    if (hashset_contains(set, 20)) {
        printf("20 exists.\n");
    }

    hashset_remove(set, 10);
    if (!hashset_contains(set, 10)) {
        printf("10 removed.\n");
    }

    printf("Size: %d\n", hashset_get_size(set));

    hashset_free(set);
    return 0;
}

**/