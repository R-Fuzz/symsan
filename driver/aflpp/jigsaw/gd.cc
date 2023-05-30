#include <stdint.h>
#include <assert.h>
#include <iostream>

#include "jit.h"
#include "input.h"
#include "grad.h"
#include "config.h"
#include "ast.h"
#include "task.h"

using namespace rgd;

#define DEBUG 0

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define SWAP64(_x)                                                             \
  ({                                                                           \
                                                                               \
    uint64_t _ret = (_x);                                                           \
    _ret =                                                                     \
        (_ret & 0x00000000FFFFFFFF) << 32 | (_ret & 0xFFFFFFFF00000000) >> 32; \
    _ret =                                                                     \
        (_ret & 0x0000FFFF0000FFFF) << 16 | (_ret & 0xFFFF0000FFFF0000) >> 16; \
    _ret =                                                                     \
        (_ret & 0x00FF00FF00FF00FF) << 8 | (_ret & 0xFF00FF00FF00FF00) >> 8;   \
    _ret;                                                                      \
                                                                               \
  })

static void dump_results(MutInput &input, std::shared_ptr<SearchTask> task) {
  int i = 0;
  for (auto it : task->inputs) {
    std::cout << "index is " << it.first << " result is " << (int)input.value[i] << std::endl;
    i++;
  }
}

static void dump_distances(std::vector<uint64_t> &distances) {
  for (size_t i = 0; i < distances.size(); i++) {
    std::cout << "distance " << i << " is " << distances[i] << std::endl;
  }
}


static void add_results(MutInput &input, std::shared_ptr<SearchTask> task) {
  int i = 0;
  // since we used a trick (allow each byte to overflow and then use add instead
  // of bitwise or to concatenate, so the overflow would be visible)
  // to allow us to manipulate each byte individually during gradient descent,
  // we need to do a bit more work to get the final result

  // first, we order the inputs by their offset
  std::map<uint32_t, uint64_t> ordered_inputs;
  for (auto it : task->inputs) {
    ordered_inputs[it.first] = input.value[i];
    i++;
  }

  // next, convert the ordered inputs to a vector for easier access
  std::vector<std::pair<uint32_t, uint64_t> > ordered_inputs_v;
  for (const auto& pair : ordered_inputs) {
    ordered_inputs_v.push_back(pair);
  }

  // finally, we calculate the final result
  uint32_t length = 1;
  uint64_t result = 0;
  uint32_t start = 0;
  for (i = 0; i < ordered_inputs_v.size();) {
    start = ordered_inputs_v[i].first;
    result = ordered_inputs_v[i].second;
    length = task->shapes[start];
    if (length == 0) { ++i; continue; }
    if (length <= 8) { // 8 bytes or less
      // first, concatenate the bytes according to the shape
      for (int j = 1; j < length; ++j) {
        result += (ordered_inputs_v[i + j].second << (8 * j));
      }
      // then extract the correct values, little endian
      for (int j = 0; j < length; ++j) {
        task->solution[start + j] = (uint8_t)((result >> (8 * j)) & 0xff);
      }
    } else { // if it's too large, just copy the value
      for (int j = 0; j < length; ++j) {
        task->solution[start + j] = ordered_inputs_v[i + j].second;
      }
    }
    i += length;
  }
}


static inline uint64_t sat_inc(uint64_t base, uint64_t inc) {
  return base + inc < base ? -1 : base + inc;
}


static uint32_t negate(uint32_t op) {
  switch (op) {
    case rgd::Equal: return rgd::Distinct;
    case rgd::Distinct: return rgd::Equal;
    case rgd::Sge: return rgd::Slt;
    case rgd::Sgt:  return rgd::Sle;
    case rgd::Sle:  return rgd::Sgt;
    case rgd::Slt:  return rgd::Sge;
    case rgd::Uge:  return rgd::Ult;
    case rgd::Ugt:  return rgd::Ule;
    case rgd::Ule:  return rgd::Ugt;
    case rgd::Ult:  return rgd::Uge;
    default: assert(false && "Non-relational op!");
  };
  return 0;
}


static uint64_t get_distance(uint32_t comp, uint64_t a, uint64_t b) {
  uint64_t dis = 0;
  switch (comp) {
    case rgd::Equal:
      if (a >= b) dis = a - b;
      else dis = b - a;
      break;
    case rgd::Distinct:
      if (a == b) dis = 1;
      else dis = 0;
      break;
    case rgd::Ult:
      if (a < b) dis = 0;
      else dis = sat_inc(a - b, 1);
      break;
    case rgd::Ule:
      if (a <= b) dis = 0;
      else dis = a - b;
      break;
    case rgd::Ugt:
      if (a > b) dis = 0;
      else dis = sat_inc(b - a, 1);
      break;
    case rgd::Uge:
      if (a >= b) dis = 0;
      else dis = b - a;
      break;
    case rgd::Slt:
      if ((int64_t)a < (int64_t)b) return 0;
      else dis = sat_inc(a - b, 1);
      break;
    case rgd::Sle:
      if ((int64_t)a <= (int64_t)b) return 0;
      else dis = a - b;
      break;
    case rgd::Sgt:
      if ((int64_t)a > (int64_t)b) return 0;
      else dis = sat_inc(b - a, 1);
      break;
    case rgd::Sge:
      if ((int64_t)a >= (int64_t)b) return 0;
      else dis = b - a;
      break;
    case rgd::Memcmp:
      dis = a ^ 1;
      break;
    case rgd::MemcmpN:
      dis = a;
      break;
    default:
      assert(false && "Non-relational op!");
  }
  return dis;
}


static uint64_t single_distance(MutInput &input, std::vector<uint64_t> &distances, std::shared_ptr<SearchTask> task, int index) {
  // only re-compute the distance of the constraints that are affected by the change
  uint64_t res = 0;
  for (uint32_t cons_id : task->cmap[index]) {
    auto& c = task->constraints[cons_id];
    auto& cm = task->consmeta[cons_id];
    int arg_idx = 0;
    for (auto const &arg : cm->input_args) {
      if (arg.first) {// symbolic
        task->scratch_args[RET_OFFSET + arg_idx] = input.value[arg.second];
      } else {
        task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
      }
      ++arg_idx;
    }
    c->fn(task->scratch_args);
    uint64_t dis = get_distance(cm->comparison, task->scratch_args[0], task->scratch_args[1]);
    distances[cons_id] = dis;
#if DEBUG
    std::cout << "single distance of constraint " << cons_id << " is " << dis << std::endl;
#endif
    res = sat_inc(res, dis);
  }
  return res;
}


static uint64_t distance(MutInput &input, std::vector<uint64_t> &distances, std::shared_ptr<SearchTask> task) {
  static int timeout = 0;
  static int solved= 0;
  uint64_t res = 0;

  for (int i = 0; i < task->constraints.size(); i++) {
    auto& c = task->constraints[i];
    auto& cm = task->consmeta[i];
    // mapping symbolic args
    int arg_idx = 0;
    for (auto const &arg : cm->input_args) {
      if (arg.first) { // symbolic
        task->scratch_args[RET_OFFSET + arg_idx] = input.value[arg.second];
      } else {
        task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
      }
      ++arg_idx;
    }
    c->fn(task->scratch_args);
    uint64_t dis = get_distance(cm->comparison, task->scratch_args[0], task->scratch_args[1]);
    distances[i] = dis;
    cm->op1 = task->scratch_args[0];
    cm->op2 = task->scratch_args[1];
#if DEBUG
    std::cout << "distance of constraint " << i << " is " << dis << std::endl;
#endif
    res = sat_inc(res, dis);
  }
  if (res == 0) {
    task->stopped = true;
    task->solved = true;
    //dump_results(input, task);
    add_results(input, task);
  }
  task->attempts++;
  if (task->attempts > MAX_EXEC_TIMES) {
    task->stopped = true;
    task->solved = false;
  }
  return res;
}


static void partial_derivative(MutInput &orig_input, size_t index, uint64_t f0, bool *sign, bool* is_linear, uint64_t *val, std::shared_ptr<SearchTask> task) {

  uint64_t orig_val = orig_input.value[index];
  uint64_t delta = 1;
  uint64_t f_plus = 0, f_minus = 0;
  uint64_t single_dis;

  // calculate f(x+delta)
  for (delta = 1; delta < 256; delta = delta << 1) {
    task->plus_distances = task->min_distances;
    orig_input.update(index, true, delta);
    single_dis = single_distance(orig_input, task->plus_distances, task, index);
    if (single_dis == 0) { // well, we got lucky and found a solution
      *sign = true;
      *is_linear = false;
      *val = 0;
      return;
    }
    f_plus = 0;
    for (int i = 0; i < task->constraints.size(); i++)
      f_plus = sat_inc(f_plus, task->plus_distances[i]);

    task->attempts += 1;
    if (task->attempts > MAX_EXEC_TIMES)
      task->stopped = true;
    if (task->stopped) { *val = 0; return; }

    if (f_plus == f0) { // if f(x+delta) == f(x), delta is not large enough
      delta = delta << 1;
    } else {
      break;
    }
  }
  orig_input.value[index] = orig_val; // restore the original value

  // calculate f(x-delta)
  for (delta = 1; delta < 256; delta = delta << 1) {
    task->minus_distances = task->min_distances;
    orig_input.update(index, false, delta);
    single_dis = single_distance(orig_input, task->minus_distances, task, index);
    if (single_dis == 0) { // well, we got lucky and found a solution
      *sign = false;
      *is_linear = false;
      *val = 0;
      return;
    }
    f_minus = 0;
    for (int i = 0; i < task->constraints.size(); i++)
      f_minus = sat_inc(f_minus, task->minus_distances[i]);

    task->attempts += 1;
    if (task->attempts > MAX_EXEC_TIMES)
      task->stopped = true;
    if (task->stopped) { *val = 0; return;}

    if (f_minus == f0) { // if f(x-delta) == f(x), delta is not large enough
      delta = delta << 1;
    } else {
      break;
    }
  }
  orig_input.value[index] = orig_val; // restore the original value

#if DEBUG
  std::cout << "calculating partial and f0 is " << f0 << " f_minus is " << f_minus << " and f_plus is " << f_plus << std::endl;
#endif

  if (f_minus < f0) {
    if (f_plus < f0) {
      if (f_minus < f_plus) {
        *sign = false;
        *is_linear = false;
        *val = f0 - f_minus;
      } else { // f_minus >= f_plus
        *sign = true;
        *is_linear = false;
        *val = f0 - f_plus;
      }
    } else { // f_plus >= f0
      *sign = false;
      *is_linear = ((f_minus != f0) && (f0 - f_minus == f_plus - f0));
      *val = f0 - f_minus;
    }
  } else { // f_minus >= f0
    if (f_plus < f0) {
      *sign = true;
      *is_linear = ((f_minus != f0) && (f_minus - f0 == f0 - f_plus));
      *val = f0 - f_plus;
    } else { // f_plus >= f0
      // reached a local optimum
      *sign = true;
      *is_linear = false;
      *val = 0;
    }
  }
}


static void compute_delta_all(MutInput &input, Grad &grad, size_t step) {
  double fstep = (double)step;
  int index = 0;
  for (auto &gradu : grad.get_value()) {
    double movement = gradu.pct * step;
    input.update(index, gradu.sign, (uint64_t)movement);
#if DEBUG
    std::cout << "compute_delta_all for index = " << index
              << ", sign = " << gradu.sign
              << ", move = " << movement << std::endl;
#endif
    index++;
  }
}


static void cal_gradient(MutInput &input, uint64_t f0, Grad &grad, std::shared_ptr<SearchTask> task) {
  uint64_t max = 0;
  int index = 0;
  for (auto &gradu : grad.get_value()) {

    if (task->stopped) {
      break;
    }
    bool sign = false;
    bool is_linear = false;
    uint64_t val = 0;

    partial_derivative(input, index, f0, &sign, &is_linear, &val, task);
    if (val > max) {
      max = val;
    }
#if DEBUG
    std::cout << "cal_gradient for index = " << index << ", offset = "
              << task->inputs[index].first << ", val = " << val << std::endl;
#endif
    //linear = linear && l;
    gradu.sign = sign;
    gradu.val = val;
    index++;
  }
}


static uint64_t descend(MutInput &input_min, MutInput &input, uint64_t f0, Grad &grad, std::shared_ptr<SearchTask> task) {
  uint64_t f_last = f0;
  input = input_min;
  bool doDelta = false;
  int deltaIdx = 0;

  uint64_t vsum = grad.val_sum();

  if (vsum > 0) {
    auto guess_step = f0 / vsum;
    compute_delta_all(input, grad, guess_step);
    uint64_t f_new = distance(input, task->distances, task);
    if (f_new >= f_last) {
      input = input_min;
    } else if (f_new == 0) {
      // found a solution
      task->stopped = true;
      task->solved = true;
      add_results(input, task);
      return 0;
    } else {
      input_min = input;
      f_last = f_new;
      task->min_distances = task->distances;
    }
  } else {
    task->distances = task->min_distances;
  }

  size_t step = 1;
  while (true) {
    while (true) {
      if (task->stopped) {
        return f_last;
      }

      uint64_t f_new = 0;
      if (doDelta) {
        double movement = grad.get_value()[deltaIdx].pct * (double)step;
        input.update(deltaIdx, grad.get_value()[deltaIdx].sign, (uint64_t)movement);
#if DEBUG
        std::cout << "update index = " << deltaIdx << ", offset = "
                  << task->inputs[deltaIdx].first << ", sign = "
                  << grad.get_value()[deltaIdx].sign
                  << ", movement = " << movement << std::endl;
#endif

        uint64_t single_dis = single_distance(input, task->distances, task, deltaIdx);
        for (int i = 0; i < task->constraints.size(); i++)
          f_new = sat_inc(f_new, task->distances[i]);
        task->attempts += 1;
        if (task->attempts > MAX_EXEC_TIMES)
          task->stopped = true;
        if (single_dis == 0) {
          // if we're doing delta and the single distance is 0
          // we're done with the current index
          break;
        }

      } else {
        compute_delta_all(input, grad, step);
        f_new = distance(input, task->distances, task);
      }

      if (f_new == 0) {
        // found a solution
        task->stopped = true;
        task->solved = true;
        add_results(input, task);
        return 0;
      } else if (f_new > f_last) { // use > to give the next larger step a chance
        //if (f_new == UINTMAX_MAX)
        break;
      }

      step *= 2;
      input_min = input;
      task->min_distances = task->distances;
      f_last = f_new;
    }

    if (grad.len() == 1) {
      break;
    } else {
      if (doDelta) deltaIdx++;
      else { deltaIdx = 0; doDelta = true;}
      while ((deltaIdx < grad.len()) && grad.get_value()[deltaIdx].pct < 0.01) {
        deltaIdx++ ;
      }
      if (deltaIdx >= grad.len()) {
        break;
      }
      input = input_min;
      task->distances = task->min_distances;
      step = 1;
    }
  }
  return f_last;
}


static uint64_t get_i2s_value(uint32_t comp, uint64_t v, bool rhs) {
  switch (comp) {
    case rgd::Equal:
    case rgd::Ule:
    case rgd::Uge:
    case rgd::Sle:
    case rgd::Sge:
      return v;
    case rgd::Distinct:
    case rgd::Ugt:
    case rgd::Sgt:
      if (rhs) return v + 1;
      else return v - 1;
    case rgd::Ult:
    case rgd::Slt:
      if (rhs) return v - 1;
      else return v + 1;
    default:
      assert(false && "Non-relational op!");
  }
  return v;
}


static uint64_t try_new_i2s_value(std::shared_ptr<const Constraint> &c, uint32_t comparison, uint64_t value, std::shared_ptr<SearchTask> task) {
  int i = 0;
  for (auto const& [offset, lidx] : c->local_map) {
    uint64_t v = ((value >> i) & 0xff);
    task->scratch_args[RET_OFFSET + lidx] = v;
    i += 8;
  }
  int arg_idx = 0;
  for (auto const& arg : c->input_args) {
    // NOTE: using the constaints input_args here (instead of the consmeta's)
    // is fine because the constants are always the same
    if (!arg.first) task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
    ++arg_idx;
  }
  c->fn(task->scratch_args);
  return get_distance(comparison, task->scratch_args[0], task->scratch_args[1]);
}


static uint64_t try_i2s(MutInput &input_min, MutInput &temp_input, uint64_t f0, std::shared_ptr<SearchTask> task) {
  temp_input = input_min;
  bool updated = false;
  for (int k = 0; k < task->constraints.size(); k++) {
    auto& c = task->constraints[k];
    auto& cm = task->consmeta[k];
    if (task->min_distances[k]) {
      if (likely(isRelationalKind(cm->comparison))) {
        // check consecutive input bytes against comparison operands
        // FIXME: add support for other input encodings
        uint64_t input = 0, input_r, value = 0, dis = -1;
        for (auto const& candidate : cm->i2s_candidates) {
          const size_t offset = candidate.first;
          const uint32_t size = candidate.second;
          if (size > 8) {
            continue;
          }
          int i = 0, t = size * 8;
          for (size_t off = offset; off < offset + size; off++) {
            const uint32_t lidx = c->local_map.at(off);
            uint64_t v = input_min.get(cm->input_args[lidx].second);
            input |= (v << i);
            input_r |= (v << (t - i - 8));
            i += 8;
          }
          if (input == cm->op1) {
            value = get_i2s_value(cm->comparison, cm->op2, true);
          } else if (input == cm->op2) {
            value = get_i2s_value(cm->comparison, cm->op1, false);
          } else {
            goto try_reverse;
          }

          // test the new value
          dis = try_new_i2s_value(c, cm->comparison, value, task);
          if (dis == 0) {
#if DEBUG
            std::cerr << "i2s updated c = " << k << " t = " << t << " input = " << input
                      << " op1 = " << cm->op1 << " op2 = " << cm->op2
                      << " cmp = " << cm->comparison << " value = " << value
                      << " old-dis = " << task->min_distances[k] << " new-dis = " << dis << std::endl;
#endif
            // successful, update the real inputs
            i = 0;
            for (size_t off = offset; off < offset + size; off++) {
              const uint32_t lidx = c->local_map.at(off);
              uint8_t v = ((value >> i) & 0xff);
              temp_input.set(cm->input_args[lidx].second, v);
              i += 8;
            }
            updated = true;
            break; // one match per comparison
          }

try_reverse:
          // try reverse encoding
          if (input_r == cm->op1) {
            value = get_i2s_value(cm->comparison, cm->op2, true);
          } else if (input_r == cm->op2) {
            value = get_i2s_value(cm->comparison, cm->op1, false);
          } else {
            continue;
          }

          // test the new value
          value = SWAP64(value) >> (64 - t); // reverse the value
          dis = try_new_i2s_value(c, cm->comparison, value, task);
          if (dis == 0) {
            // successful, update the real inputs
            i = 0;
            for (size_t off = offset; off < offset + size; off++) {
              const uint32_t lidx = c->local_map.at(off);
              uint8_t v = ((value >> i) & 0xff);
              // uint8_t v = ((value >> (t - i - 8)) & 0xff);
              temp_input.set(cm->input_args[lidx].second, v);
              i += 8;
            }
            updated = true;
            break;
          }
        } // end foreach candidate
      } else if (cm->comparison == rgd::Memcmp) {
        size_t const_index = 0;
        for (auto const& arg : c->input_args) {
          if (!arg.first) break;
          const_index++;
        }
        // memcmp(s1, s2) is i2s_feasible iff s1 is constant
        // try copy s1 to s2
        if (const_index == c->input_args.size()) continue;
        assert(cm->i2s_candidates.size() == 1 && "memcmp should have only one candidate");
        size_t offset = cm->i2s_candidates[0].first;
        uint32_t size = cm->i2s_candidates[0].second;
        assert(size == c->local_map.size() && "input size mismatch");
        int i = 0;
        uint64_t value = 0;
        for (size_t off = offset; off < offset + size; off++) {
          const uint32_t lidx = c->local_map.at(off);
          if (i == 0)
            value = c->input_args[const_index].second;
          uint8_t v = ((value >> i) & 0xff);
          temp_input.set(cm->input_args[lidx].second, v);
          i += 8;
          if (i == 64) {
            const_index++; // move on to the next 64-bit chunk
            i = 0;
          }
        }
        updated = true;
      }
    }
  }
  if (updated) {
    uint64_t f_new = distance(temp_input, task->distances, task);
    if (f_new < f0) {
      // std::cout << "i2s succeeded: " << f0 << " -> " << f_new << std::endl;
      input_min = temp_input;
      task->min_distances = task->distances;
      return f_new;
    }
  }
  return f0;
}

static uint64_t repick_start_point(MutInput &input_min, std::shared_ptr<SearchTask> task) {
  input_min.randomize();
  uint64_t ret = distance(input_min, task->min_distances, task);
  return ret;
}


static uint64_t reload_input(MutInput &input_min, std::shared_ptr<SearchTask> task) {
  input_min.assign(task->inputs);
#if 0
  printf("assign realod\n");
  for(auto itr : task->inputs) {
    printf("offset %u value %u\n", itr.first, itr.second);
  }
#endif
  uint64_t ret = distance(input_min, task->min_distances, task);
  return ret;
}

bool rgd::gd_entry(std::shared_ptr<SearchTask> task) {
  MutInput input(task->inputs.size());
  MutInput scratch_input(task->inputs.size());
  task->attempts = 0;

  uint64_t f0 = reload_input(input, task);
  f0 = try_i2s(input, scratch_input, f0, task);
  if (task->stopped)
    return task->solved;

  if (f0 == UINTMAX_MAX)
    return false;

  int ep_i = 0;

  Grad grad(input.len());

  while (true) {
    if (task->stopped) {
      break;
    }
#if DEBUG
    std::cout << "<<< epoch=" << ep_i << " f0=" << f0 << std::endl;
    dump_results(input, task);
    dump_distances(task->min_distances);
#endif

    cal_gradient(input, f0, grad, task);

    int g_i = 0;
    while (grad.max_val() == 0) {
      if (g_i > MAX_NUM_MINIMAL_OPTIMA_ROUND) {
        break;
      }
      if (task->stopped)
        break;
      g_i++;
      //f0 = repick_start_point(input, f0, rng);
      //f0 = reload_input(input);
      f0 = repick_start_point(input, task);
      f0 = try_i2s(input, scratch_input, f0, task);
      if (task->stopped)
        break;
      grad.clear();
      cal_gradient(input, f0, grad, task);
    }
    if (task->stopped || g_i > MAX_NUM_MINIMAL_OPTIMA_ROUND) {
      //std::cout << "trapped in local optimia for too long" << std::endl;
      break;
    }
    //TODO
    grad.normalize();
    f0 = descend(input, scratch_input, f0, grad, task);
    ep_i += 1;
    //if (ep_i == 2) break;
  }

  return task->solved;
}
