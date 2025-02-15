#ifndef MY_HASHMAP_H
#define MY_HASHMAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "defs.h"
#include "hash.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    u32* keys;
    int* values;
    SlotState* states;
    int capacity;
    int size;
    float loadFactorThreshold;
} HashMap;

// Creates a new hashmap with the given initial capacity and load factor threshold.
HashMap* hashmap_create(int initialCapacity);

// Frees the memory associated with the hashmap.
void hashmap_free(HashMap* map);

// Inserts or updates the key with the given value.
// Returns true if a new key was inserted, or false if an existing key was updated.
bool hashmap_put(HashMap* map, u32 key, int value);

// Retrieves a pointer to the value associated with the key.
// If the key is found, returns a pointer to the stored value; otherwise, returns NULL.
int* hashmap_get(const HashMap* map, u32 key);

// Returns true if the key exists in the hashmap.
bool hashmap_contains(const HashMap* map, u32 key);

// Removes the key (and its associated value) from the hashmap.
// Returns true if the key was removed, or false if the key was not found.
bool hashmap_remove(HashMap* map, u32 key);

// Returns the number of key-value pairs in the hashmap.
int hashmap_get_size(const HashMap* map);

#ifdef __cplusplus
}
#endif

#endif // MY_HASHMAP_H

// --------------------------------------------------------------------------
/**
// Example usage:
#include <stdio.h>
#include "hashmap.h"

int main(void) {
    HashMap* map = hashmap_create(8);
    if (!map) {
        fprintf(stderr, "Failed to create hashmap.\n");
        return 1;
    }
    
    hashmap_put(map, 10, 100);
    hashmap_put(map, 20, 200);
    hashmap_put(map, 30, 300);
    
    u32* value = hashmap_get(map, 20);
    if (value) {
        printf("Value for key 20: %u\n", *value);
    } else {
        printf("Key 20 not found.\n");
    }
    
    if (hashmap_contains(map, 10)) {
        printf("Key 10 exists in the hashmap.\n");
    } else {
        printf("Key 10 does not exist.\n");
    }
    
    hashmap_put(map, 20, 250);
    
    value = hashmap_get(map, 20);
    if (value) {
        printf("Updated value for key 20: %u\n", *value);
    }
    
    if (hashmap_remove(map, 10)) {
        printf("Key 10 removed successfully.\n");
    } else {
        printf("Failed to remove key 10.\n");
    }
    
    printf("Current hashmap size: %d\n", hashmap_get_size(map));
    
    hashmap_free(map);
    return 0;
}
**/