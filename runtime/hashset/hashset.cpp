#include "hashset.h"

static int roundUpToPowerOfTwo(int x) {
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

HashSet::HashSet(int initialCapacity, float loadFactor)
    : size(0), loadFactorThreshold(loadFactor)
{
    capacity = roundUpToPowerOfTwo(initialCapacity);
    keys = new u32[capacity];
    states = new SlotState[capacity];
    for (int i = 0; i < capacity; i++) {
        states[i] = SLOTEMPTY;
    }
}

HashSet::~HashSet() {
    delete[] keys;
    delete[] states;
}

bool HashSet::insert(u32 key) {
    if (contains(key)) {
        return false;
    }
    unsigned int index = hash1(key);
    unsigned int step = hash2(key);
    for (int i = 0; i < capacity; i++) {
        if (states[index] == SLOTEMPTY || states[index] == SLOTDELETED) {
            keys[index] = key;
            states[index] = SLOTUSED;
            size++;
            checkLoadFactorAndRehash();
            return true;
        }
        index = (index + step) & (capacity - 1);
    }
    return false;
}

int HashSet::getSize() const {
     return size; 
}

bool HashSet::contains(u32 key) const {
    unsigned int index = hash1(key);
    unsigned int step = hash2(key);
    while (states[index] != SLOTEMPTY) {
        if (states[index] == SLOTUSED && keys[index] == key) {
            return true;
        }
        index = (index + step) & (capacity - 1);
    }
    return false;
}

bool HashSet::remove(u32 key) {
    unsigned int index = hash1(key);
    unsigned int step = hash2(key);
    while (states[index] != SLOTEMPTY) {
        if (states[index] == SLOTUSED && keys[index] == key) {
            states[index] = SLOTDELETED;
            size--;
            return true;
        }
        index = (index + step) & (capacity - 1);
    }
    return false;
}

void HashSet::checkLoadFactorAndRehash() {
    float currentLoadFactor = static_cast<float>(size) / static_cast<float>(capacity);
    if (currentLoadFactor > loadFactorThreshold) {
        rehash(capacity * 2);
    }
}

void HashSet::rehash(int newCapacity) {
    u32* oldKeys = keys;
    SlotState* oldStates = states;
    int oldCapacity = capacity;

    capacity = newCapacity;
    keys = new u32[capacity];
    states = new SlotState[capacity];
    for (int i = 0; i < capacity; i++) {
        states[i] = SLOTEMPTY;
    }

    int oldSize = size;
    size = 0;

    for (int i = 0; i < oldCapacity; i++) {
        if (oldStates[i] == SLOTUSED) {
            insert(oldKeys[i]);
        }
    }

    delete[] oldKeys;
    delete[] oldStates;
}
