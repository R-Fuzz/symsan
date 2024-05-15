#ifndef HASH_TABLE
#define HASH_TABLE

#include <utility>

struct Hash_table {
  virtual std::pair<int, bool> search(int key) = 0; 
  virtual void                 insert(int key, int val) = 0;
  virtual void                 remove(int key) = 0;
};

#endif
