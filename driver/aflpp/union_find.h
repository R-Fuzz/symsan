#pragma once

#include <stdint.h>
#include <vector>
#include <unordered_set>

namespace rgd {

// disjoint set data structure
class UnionFind {
public:
  static const size_t INVALID = (size_t)-1;

  UnionFind() : size_(0) {};
  UnionFind(size_t size) {
    reset(size);
  };

  void reset(size_t size) {
    size_ = size;
    parent.resize(size);
    next.resize(size);
    rank.resize(size);
    for (size_t i = 0; i < size; ++i) {
      parent[i] = i;
      next[i] = i;
      rank[i] = 0;
    }
  }

  // find the root of the set containing x
  size_t find(size_t x) {
    if (x >= size_) return INVALID;

    size_t p = parent[x];
    while (x != p) {
      size_t gp = parent[p];
      parent[x] = gp;
      x = p;
      p = gp;
    }
    return x;
  }

  // merge the sets containing x and y, return new root
  size_t merge(size_t x, size_t y) {
    if (x >= size_) return INVALID;
    if (y >= size_) return INVALID;

    size_t x_root = find(x);
    size_t y_root = find(y);
    if (x_root == y_root) return x_root;

    // merge link list
    size_t x_next = next[x_root];
    next[x_root] = next[y_root];
    next[y_root] = x_next;

    if (rank[x_root] < rank[y_root]) {
      parent[x_root] = y_root;
      return y_root;
    } else if (rank[x_root] > rank[y_root]) {
      parent[y_root] = x_root;
      return x_root;
    } else {
      parent[y_root] = x_root;
      rank[x_root]++;
      return x_root;
    }
  }

  // get the set containing x
  size_t get_set(size_t x, std::unordered_set<size_t> &set) {
    if (x >= size_) return INVALID;
    size_t temp = x;
    set.clear();
    set.insert(temp);
    while (next[temp] != x) {
      temp = next[temp];
      set.insert(temp);
    }
    return set.size();
  }

private:
  size_t size_;
  std::vector<size_t> parent;
  std::vector<size_t> next;
  std::vector<size_t> rank;
};

};