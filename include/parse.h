#pragma once

#include "dfsan/dfsan.h"

#include <stdint.h>
#include <string.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace symsan {

using input_t = std::pair<const uint8_t*, size_t>;
using offset_t = std::pair<uint32_t, uint32_t>;
struct offset_hash {
  std::size_t operator()(const offset_t &off) const {
    uint64_t key = off.first;
    key <<= 32;
    key |= off.second;
    return std::hash<uint64_t>{}(key);
  }
};

template <class T>
class ASTParser {
public:
  ASTParser() = delete;
  ASTParser(void *base, size_t size)
    : base_(static_cast<dfsan_label_info*>(base)),
      size_(size / sizeof(dfsan_label_info)),
      prev_task_id_(0) {}
  virtual ~ASTParser() {}

  virtual int restart(std::vector<input_t> &inputs) {
    (void)inputs;
    memcmp_cache_.clear();
    return 0;
  }
  /// @brief Parse a conditional branch
  /// @param label the label of the condition
  /// @param result the result of the condition
  /// @param add_nested whether to add nested constraints
  /// @param tasks the tasks to be added
  /// @return 0 on success, -1 on failure
  virtual int parse_cond(dfsan_label label, bool result, bool add_nested,
                         std::vector<uint64_t> &tasks) = 0;
  /// @brief Parse a GEP instruction with symbolic index
  /// @param ptr_label symbol label of the pointer (e.g., bounds info)
  /// @param ptr actual pointer value
  /// @param index_label symbolic label of the index
  /// @param index actual index value
  /// @param num_elems number of elements if ptr is an array
  /// @param elem_size size of each element
  /// @param current_offset current offset from previous GEP
  /// @param enum_index whether to enumerate all possible indices
  /// @param tasks tasks to be added
  /// @return 0 on success, -1 on failure
  virtual int parse_gep(dfsan_label ptr_label, uptr ptr,
                        dfsan_label index_label, int64_t index,
                        uint64_t num_elems, uint64_t elem_size,
                        int64_t current_offset, bool enum_index,
                        std::vector<uint64_t> &tasks) = 0;

  /// @brief Add a constraint, typically from symbolic offset
  /// @param label symbolic label of the constraint
  /// @param result concrete value of the constraint
  /// @return 0 on success, -1 on failure
  virtual int add_constraints(dfsan_label label, uint64_t result) = 0;

  virtual int record_memcmp(dfsan_label label, uint8_t* buf, size_t size) {
    auto content = std::make_unique<uint8_t[]>(size);
    memcpy(content.get(), buf, size);
    memcmp_cache_.insert({label, std::move(content)});
    return 0;
  };

  // use shared_ptr to auto-free task
  virtual std::shared_ptr<T> retrieve_task(uint64_t id) {
    auto it = tasks_.find(id);
    if (it == tasks_.end()) {
      return nullptr;
    }
    auto tmp = std::move(it->second);
    tasks_.erase(it);
    return tmp;
  }

protected:
  inline dfsan_label_info* get_label_info(dfsan_label label) {
    if (label >= size_) {
      throw std::out_of_range("label too large " + std::to_string(label));
    }
    return &base_[label];
  }

  inline uint64_t save_task(std::shared_ptr<T> task) {
    uint64_t tid = prev_task_id_++;
    tasks_.insert({tid, task});
    return tid;
  }

  dfsan_label_info *base_;
  size_t size_;
  uint64_t prev_task_id_;
  std::unordered_map<uint64_t, std::shared_ptr<T>> tasks_;
  std::unordered_map<dfsan_label, std::unique_ptr<uint8_t[]>> memcmp_cache_;
};

}; // namespace symsan
