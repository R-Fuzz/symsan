#ifndef _INPUT_H_
#define _INPUT_H_
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string.h>
#include <stdlib.h>
#include <utility>

namespace rgd {

class InputMeta {
public:
  bool sign;
  size_t offset;
  size_t size;
};


class MutInput {
public:
  // std::vector<uint8_t> value;
  uint64_t* value;
  // std::vector<InputMeta> meta;
  size_t size_;
  size_t get_size();
  MutInput(size_t size);
  ~MutInput();
  void dump();
  uint64_t len();
  uint64_t val_len();
  void randomize();
  //random
  char r_s[256];
  struct random_data r_d;
  int32_t r_val;
  int32_t r_idx;
  uint8_t get_rand();

  uint8_t get(const size_t i);
  void update(size_t index, bool direction, uint64_t delta);
  void flip(size_t index, size_t bit_index);
  void set(const size_t index, uint8_t value);
  void assign(std::vector<std::pair<uint32_t,uint8_t>> &input);
  MutInput& operator=(const MutInput &other);

  static void copy(MutInput *dst, const MutInput *src)
  {
    uint64_t *dst_value = dst->value;
    memcpy(dst, src, sizeof(MutInput));
    if (!dst_value)
      dst->value = (uint64_t*)malloc(src->size_ * sizeof(uint64_t));
    else
      dst->value = dst_value;
    memcpy(dst->value, src->value, src->size_ * sizeof(uint64_t));
  }
};

}; // namespace rgd

#endif
