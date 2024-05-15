#pragma once

#include "task.h"

#include <deque>
#include <memory>

namespace rgd {

class TaskManager {
public:
  virtual ~TaskManager() {}
  virtual bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) = 0;
  virtual std::shared_ptr<SearchTask> get_next_task() = 0;
  virtual size_t get_num_tasks() = 0;
};

class FIFOTaskManager : public TaskManager {
public:
  bool add_task(std::shared_ptr<BranchContext> ctx, std::shared_ptr<SearchTask> task) override {
    (void)ctx;
    tasks.push_back(std::move(task));
    return true;
  }

  std::shared_ptr<SearchTask> get_next_task() override {
    if (tasks.empty()) return nullptr;
    auto task = std::move(tasks.front());
    tasks.pop_front();
    return task;
  }

  size_t get_num_tasks() override {
    return tasks.size();
  }

private:
  std::deque<task_t> tasks;
};

};  // namespace rgd
