#include "hashmap.h"
#include <stdlib.h>
#include <stdio.h>

static bool insert_no_rehash(HashMap* map, u32 key, int value) {
    unsigned int index = hash1(key, map->capacity);
    unsigned int step = hash2(key, map->capacity);
    for (int i = 0; i < map->capacity; i++) {
        if (map->states[index] == SLOTEMPTY || map->states[index] == SLOTDELETED) {
            map->keys[index] = key;
            map->values[index] = value;
            map->states[index] = SLOTUSED;
            map->size++;
            return true;
        }
        index = (index + step) & (map->capacity - 1);
    }
    return false;
}

static bool rehash(HashMap* map, int newCapacity) {
    u32* oldKeys = map->keys;
    int* oldValues = map->values;
    SlotState* oldStates = map->states;
    int oldCapacity = map->capacity;

    map->capacity = newCapacity;
    u32* keys_ptr = (u32*)malloc(sizeof(u32) * map->capacity);
    int* values_ptr = (int*)malloc(sizeof(int) * map->capacity);
    SlotState* states_ptr = (SlotState*)malloc(sizeof(SlotState) * map->capacity);
    if (!keys_ptr || !states_ptr || !values_ptr) {
        if (keys_ptr) {
            free(keys_ptr);
        }
        if (states_ptr) {
            free(states_ptr);
        }
        if (values_ptr) {
            free(values_ptr);
        }
        map->capacity = oldCapacity;
        return false;
    }
    map->keys = keys_ptr;
    map->values = values_ptr;
    map->states = states_ptr;

    for (int i = 0; i < map->capacity; i++) {
        map->states[i] = SLOTEMPTY;
    }
    map->size = 0;

    for (int i = 0; i < oldCapacity; i++) {
        if (oldStates[i] == SLOTUSED) {
            insert_no_rehash(map, oldKeys[i], oldValues[i]);
        }
    }

    free(oldKeys);
    free(oldValues);
    free(oldStates);
    return true;
}

static void checkLoadFactorAndRehash(HashMap* map) {
    float currentLoadFactor = (float)map->size / (float)map->capacity;
    if (currentLoadFactor > map->loadFactorThreshold) {
        if (!rehash(map, map->capacity * 2)) {
            fprintf(stderr, "Warning: Rehashing failed. The hash set remains in an unrehashed state.\n");
        }
    }
}

HashMap* hashmap_create(int initialCapacity) {
    float loadFactor = 0.75f;
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    if (!map) {
        return NULL;
    }
    map->capacity = roundUpToPowerOfTwo(initialCapacity);
    map->keys = (u32*)malloc(sizeof(u32) * map->capacity);
    map->values = (int*)malloc(sizeof(int) * map->capacity);
    map->states = (SlotState*)malloc(sizeof(SlotState) * map->capacity);
    if (!map->keys || !map->values || !map->states) {
        free(map->keys);
        free(map->values);
        free(map->states);
        free(map);
        return NULL;
    }
    for (int i = 0; i < map->capacity; i++) {
        map->states[i] = SLOTEMPTY;
    }
    map->size = 0;
    map->loadFactorThreshold = loadFactor;
    return map;
}

void hashmap_free(HashMap* map) {
    if (map) {
        free(map->keys);
        free(map->values);
        free(map->states);
        free(map);
    }
}

bool hashmap_put(HashMap* map, u32 key, int value) {
    unsigned int index = hash1(key, map->capacity);
    unsigned int step = hash2(key, map->capacity);
    int firstDeleted = -1;

    for (int i = 0; i < map->capacity; i++) {
        if (map->states[index] == SLOTEMPTY) {
            if (firstDeleted != -1) {
                index = firstDeleted;
            }
            map->keys[index] = key;
            map->values[index] = value;
            map->states[index] = SLOTUSED;
            map->size++;
            checkLoadFactorAndRehash(map);
            return true;
        }
        else if (map->states[index] == SLOTDELETED) {
            if (firstDeleted == -1) {
                firstDeleted = index;
            }
        }
        else if (map->states[index] == SLOTUSED && map->keys[index] == key) {
            map->values[index] = value;
            return false;
        }
        index = (index + step) & (map->capacity - 1);
    }
    if (firstDeleted != -1) {
        map->keys[firstDeleted] = key;
        map->values[firstDeleted] = value;
        map->states[firstDeleted] = SLOTUSED;
        map->size++;
        checkLoadFactorAndRehash(map);
        return true;
    }
    return false;
}

int* hashmap_get(const HashMap* map, u32 key) {
    unsigned int index = hash1(key, map->capacity);
    unsigned int step = hash2(key, map->capacity);
    for (int i = 0; i < map->capacity; i++) {
        if (map->states[index] == SLOTEMPTY) {
            return NULL;
        }
        if (map->states[index] == SLOTUSED && map->keys[index] == key) {
            return &map->values[index];
        }
        index = (index + step) & (map->capacity - 1);
    }
    return NULL;
}

bool hashmap_contains(const HashMap* map, u32 key) {
    return hashmap_get(map, key) != NULL;
}

bool hashmap_remove(HashMap* map, u32 key) {
    unsigned int index = hash1(key, map->capacity);
    unsigned int step = hash2(key, map->capacity);
    for (int i = 0; i < map->capacity; i++) {
        if (map->states[index] == SLOTEMPTY) {
            return false;
        }
        if (map->states[index] == SLOTUSED && map->keys[index] == key) {
            map->states[index] = SLOTDELETED;
            map->size--;
            return true;
        }
        index = (index + step) & (map->capacity - 1);
    }
    return false;
}

int hashmap_get_size(const HashMap* map) {
    return map->size;
}
