#include "hashset.h"
#include <stdlib.h>
#include <stdio.h>

// Helper function: inserts a key into the set without checking for duplicates
// or load factor. Used during rehashing.
static bool insert_no_rehash(HashSet* set, u32 key) {
    unsigned int index = hash1(key, set->capacity);
    unsigned int step = hash2(key, set->capacity);
    for (int i = 0; i < set->capacity; i++) {
        if (set->states[index] == SLOTEMPTY || set->states[index] == SLOTDELETED) {
            set->keys[index] = key;
            set->states[index] = SLOTUSED;
            set->size++;
            return true;
        }
        index = (index + step) & (set->capacity - 1);
    }
    return false;
}

// Rehashes the set into a new table with the specified new capacity.
static bool rehash(HashSet* set, int newCapacity) {
    u32* oldKeys = set->keys;
    SlotState* oldStates = set->states;
    int oldCapacity = set->capacity;

    set->capacity = newCapacity;
    u32* keys_ptr = (u32*)malloc(sizeof(u32) * set->capacity);
    SlotState* states_ptr = (SlotState*)malloc(sizeof(SlotState) * set->capacity);
    if (!keys_ptr || !states_ptr) {
        if (keys_ptr) {
            free(keys_ptr);
        }
        if (states_ptr) {
            free(states_ptr);
        }
        set->capacity = oldCapacity;
        return false;
    }
    set->keys = keys_ptr;
    set->states = states_ptr;
    for (int i = 0; i < set->capacity; i++) {
        set->states[i] = SLOTEMPTY;
    }
    set->size = 0;

    for (int i = 0; i < oldCapacity; i++) {
        if (oldStates[i] == SLOTUSED) {
            insert_no_rehash(set, oldKeys[i]);
        }
    }

    free(oldKeys);
    free(oldStates);
    return true;
}

// Checks if the current load factor exceeds the threshold and rehashes if needed.
static void checkLoadFactorAndRehash(HashSet* set) {
    float currentLoadFactor = (float)set->size / (float)set->capacity;
    if (currentLoadFactor > set->loadFactorThreshold) {
        if (!rehash(set, set->capacity * 2)) {
            fprintf(stderr, "Warning: Rehashing failed. The hash set remains in an unrehashed state.\n");
        }
    }
}

HashSet* hashset_create(int initialCapacity) {
    float loadFactor = 0.75f;
    HashSet* set = (HashSet*)malloc(sizeof(HashSet));
    if (!set) {
        return NULL;
    }
    set->capacity = roundUpToPowerOfTwo(initialCapacity);
    set->keys = (u32*)malloc(sizeof(u32) * set->capacity);
    set->states = (SlotState*)malloc(sizeof(SlotState) * set->capacity);
    if (!set->keys || !set->states) {
        free(set->keys);
        free(set->states);
        free(set);
        return NULL;
    }
    for (int i = 0; i < set->capacity; i++) {
        set->states[i] = SLOTEMPTY;
    }
    set->size = 0;
    set->loadFactorThreshold = loadFactor;
    return set;
}

void hashset_free(HashSet* set) {
    if (set) {
        free(set->keys);
        free(set->states);
        free(set);
    }
}

bool hashset_insert(HashSet* set, u32 key) {
    if (hashset_contains(set, key)) {
        return false;
    }
    unsigned int index = hash1(key, set->capacity);
    unsigned int step = hash2(key, set->capacity);
    for (int i = 0; i < set->capacity; i++) {
        if (set->states[index] == SLOTEMPTY || set->states[index] == SLOTDELETED) {
            set->keys[index] = key;
            set->states[index] = SLOTUSED;
            set->size++;
            checkLoadFactorAndRehash(set);
            return true;
        }
        index = (index + step) & (set->capacity - 1);
    }
    return false;
}

bool hashset_contains(const HashSet* set, u32 key) {
    unsigned int index = hash1(key, set->capacity);
    unsigned int step = hash2(key, set->capacity);
    for (int i = 0; i < set->capacity; i++) {
        if (set->states[index] == SLOTEMPTY) {
            return false;
        }
        if (set->states[index] == SLOTUSED && set->keys[index] == key) {
            return true;
        }
        index = (index + step) & (set->capacity - 1);
    }
    return false;
}

bool hashset_remove(HashSet* set, u32 key) {
    unsigned int index = hash1(key, set->capacity);
    unsigned int step = hash2(key, set->capacity);
    for (int i = 0; i < set->capacity; i++) {
        if (set->states[index] == SLOTEMPTY) {
            return false;
        }
        if (set->states[index] == SLOTUSED && set->keys[index] == key) {
            set->states[index] = SLOTDELETED;
            set->size--;
            return true;
        }
        index = (index + step) & (set->capacity - 1);
    }
    return false;
}

int hashset_get_size(const HashSet* set) {
    return set->size;
}
