#ifndef LOCKFREE_HASH_TABLE
#define LOCKFREE_HASH_TABLE

#define MAX_BUF 256

#include "hash_table.h"
#include <vector>
#include <array>

struct Hash_entry {
  int key;
  int val;
};

// Alternate count_ptr definition using unused bits
typedef Hash_entry* Count_ptr;

enum Find_result { FIRST, SECOND, NIL };

struct Lockfree_hash_table {
  Lockfree_hash_table(int capacity, int thread_count);
  ~Lockfree_hash_table();
  
  std::pair<int, bool> search(int key, int tid);
  void                 insert(int key, int val, int tid);
  void                 remove(int key, int tid);

private:
  Count_ptr *table[2];  
  int size1;
  int size2;

  std::vector<std::array<Hash_entry*, MAX_BUF>>   rlist;
  std::vector<int>                                rcount;
  std::vector<std::array<Hash_entry*, 2>>         hp_rec;

  int hash1(int key);
  int hash2(int key);
  bool check_counter(int ts1, int ts2, int ts1x, int ts2x);
  Find_result find(int key, Count_ptr &ptr1, Count_ptr &ptr2, int tid);
  bool relocate(int which, int index, int tid);
  void help_relocate(int which, int index, bool initiator, int tid);
  void del_dup(int idx1, Count_ptr ptr1, int idx2, Count_ptr ptr2, int tid);

  void retire_node(Hash_entry* node, int tid);
  void scan(int tid);
};
#endif
