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

static void dumpResults(MutInput &input, std::shared_ptr<SearchTask> task) {
  int i = 0;
  for (auto it : task->inputs) {
    std::cout << "index is " << it.first << " result is " << (int)input.value[i] << std::endl;
    i++;
  }
}


static void addResults(MutInput &input, std::shared_ptr<SearchTask> task) {
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
    // first, concatenate the bytes according to the shape
    for (int j = 1; j < length; ++j) {
      result += (ordered_inputs_v[i + j].second << (8 * j));
    }
    // then extract the correct values, little endian
    for (int j = 0; j < length; ++j) {
      task->solution[start + j] = (uint8_t)((result >> (8 * j)) & 0xff);
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


static uint64_t getDistance(uint32_t comp, uint64_t a, uint64_t b) {
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
    default:
      assert(false && "Non-relational op!");
  }
  return dis;
}


static void single_distance(MutInput &input, std::shared_ptr<SearchTask> task, int index) {
  // only re-compute the distance of the constraints that are affected by the change
  for (uint32_t cons_id : task->cmap[index]) {
    auto& c = task->constraints[cons_id];
    auto& cm = task->consmeta[cons_id];
    int arg_idx = 0;
    for (auto arg : cm->input_args) {
      if (arg.first) {// symbolic
        task->scratch_args[RET_OFFSET + arg_idx] = (uint64_t)input.value[arg.second];
      } else {
        task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
      }
      ++arg_idx;
    }
    c->fn(task->scratch_args);
    uint64_t dis = getDistance(cm->comparison, task->scratch_args[0], task->scratch_args[1]);
    task->distances[cons_id] = dis;
  }
}


static uint64_t distance(MutInput &input, std::shared_ptr<SearchTask> task) {
  static int timeout = 0;
  static int solved= 0;
  uint64_t res = 0;
  uint64_t dis0 = 0;

  for (int i = 0; i < task->constraints.size(); i++) {
    auto& c = task->constraints[i];
    auto& cm = task->consmeta[i];
    // mapping symbolic args
    int arg_idx = 0;
    for (auto arg : cm->input_args) {
      if (arg.first) { // symbolic
        task->scratch_args[RET_OFFSET + arg_idx] = (uint64_t)input.value[arg.second];
      } else {
        task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
      }
      ++arg_idx;
    }
    // for(int p=0;p<task->n_sym_args+task->n_const_args;p++)
    //   std::cout << (int)task->scratch_args[p]<<", ";
    // std::cout << std::endl;
    c->fn(task->scratch_args);
    uint64_t dis = getDistance(cm->comparison, task->scratch_args[0], task->scratch_args[1]);
    task->distances[i] = dis;
    cm->op1 = task->scratch_args[0];
    cm->op2 = task->scratch_args[1];
    if (i == 0) dis0 = dis;
    /*
       if (dis == 0 && i == 0 && !task->opti_hit) {
       task->opti_hit = true;
       addOptiResults(input, task);
       }
    */
    //printf("func called and expr %d, comparison %d, arg0 %lu and arg1 %lu and return value is %lu \n",i, c.comparison, task->scratch_args[0], task->scratch_args[1], dis);
    if (likely(dis > 0)) {
      res = sat_inc(res, dis);
    }
  }
  if (res == 0) {
    task->stopped = true;
    task->solved = true;
    //dumpResults(input, task);
    //task->scratch_args[24] = task->scratch_args[24] & 0x1f;
    addResults(input, task);
  }
  task->attempts++;
  if (task->attempts > MAX_EXEC_TIMES) {
    task->stopped = true;
    task->solved = false;
  }
  return res;
}


static void partial_derivative(MutInput &orig_input, size_t index, uint64_t f0, bool *sign, bool* is_linear, uint64_t *val, std::shared_ptr<SearchTask> task) {
  //TODO assign constructors
  //MutInput input = orig_input;
  //std::cout << "calculating partial derivative and orig_input is " << orig_input.get(0) << " and " << orig_input.get(1) << std::endl;
  //std::cout << "calculating partial derivative and input is " << input.get(0) << " and " << input.get(1) << std::endl;
  //int idx = 0;
  //for(auto i : orig_input.value)
  //task->scratch_args[idx++] = i;

  uint8_t orig_val = orig_input.get(index);
  //uint8_t orig_val = task->scratch_args[index];

  // calculate f(x+1)
  orig_input.update(index, true, 1);
  single_distance(orig_input, task, index);
  uint64_t f_plus = 0;
  for (int i = 0; i < task->constraints.size(); i++)
    f_plus = sat_inc(f_plus, task->distances[i]);

  task->attempts += 1;
  if (task->attempts > MAX_EXEC_TIMES)
    task->stopped = true;
  orig_input.set(index, orig_val);
  task->distances = task->orig_distances;
  if (task->stopped) { *val = 0; return; }

  // calculate f(x-1)
  orig_input.update(index, false, 1);
  uint64_t f_minus = 0;
  single_distance(orig_input, task, index);
  for (int i = 0; i < task->constraints.size(); i++)
    f_minus += task->distances[i];

  task->attempts += 1;
  if (task->attempts > MAX_EXEC_TIMES)
    task->stopped = true;
  orig_input.set(index, orig_val);
  task->distances = task->orig_distances;
  if (task->stopped) { *val = 0; return;}

  //std::cout << "calculating partial and f0 is " << f0 << " f_minus is" << f_minus << " and f_plus is " << f_plus << std::endl;

  if (f_minus < f0) {
    if (f_plus < f0) {
      if (f_minus < f_plus) {
        *sign = false;
        *is_linear = false;
        *val = f0 - f_minus;
      } else {
        *sign = true;
        *is_linear = false;
        *val = f0 - f_plus;
      }
    } else {
      *sign = false;
      *is_linear = ((f_minus != f0) && (f0 - f_minus == f_plus -f0));
      *val = f0 -f_minus;
    }
  } else {
    if (f_plus < f0) {
      *sign = true;
      *is_linear = ((f_minus != f0) && (f_minus - f0 == f0 - f_plus));
      *val = f0 - f_plus;
    }
    else {
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
    index++;
  }
}


static void cal_gradient(MutInput &input, uint64_t f0, Grad &grad, std::shared_ptr<SearchTask> task) {
  uint64_t max = 0;
  int index = 0;
  for (auto &gradu : grad.get_value()) {

    //std::cout << "cal_gradient" << std::endl;
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
    uint64_t f_new = distance(input,task);
    if (f_new >= f_last) {
      input = input_min;
    } else {
      input_min = input;
      f_last = f_new;
    }
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

        single_distance(input, task, deltaIdx);
        for (int i = 0; i < task->constraints.size(); i++)
          f_new += task->distances[i];
        task->attempts += 1;
        if (task->attempts > MAX_EXEC_TIMES)
          task->stopped = true;

      } else {
        compute_delta_all(input, grad, step);
        f_new = distance(input,task);
      }


      if (f_new >= f_last) {
        //if (f_new == UINTMAX_MAX)
        break;
      }

      step *= 2;
      input_min = input;
      f_last = f_new;
    }
    //break;

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
  for (auto arg : c->input_args) {
    // NOTE: using the constaints input_args here (instead of the consmeta's)
    // is fine because the constants are always the same
    if (!arg.first) task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
    ++arg_idx;
  }
  c->fn(task->scratch_args);
  return getDistance(comparison, task->scratch_args[0], task->scratch_args[1]);
}


static uint64_t try_i2s(MutInput &input_min, MutInput &temp_input, uint64_t f0, std::shared_ptr<SearchTask> task) {
  temp_input = input_min;
  bool updated = false;
  for (int k = 0; k < task->constraints.size(); k++) {
    auto& c = task->constraints[k];
    auto& cm = task->consmeta[k];
    if (task->distances[k] && cm->i2s_feasible) {
      // check concatenated inputs against comparison operands
      // FIXME: add support for other input encodings
      uint64_t input = 0, input_r, value = 0, dis = -1;
      int i = 0, t = c->local_map.size() * 8;
      for (auto const& [offset, lidx] : c->local_map) {
        input |= (input_min.get(cm->input_args[lidx].second) << i);
        input_r |= (input_min.get(cm->input_args[lidx].second) << (t - i - 8));
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
        std::cout << "i2s updated c = " << k << " t = " << t << " input = " << input
                  << " op1 = " << cm->op1 << " op2 = " << cm->op2
                  << " cmp = " << cm->comparison << " value = " << value
                  << " old-dis = " << task->distances[k] << " new-dis = " << dis << std::endl;
#endif
        // successful, update the real inputs
        i = 0;
        for (auto const& [offset, lidx] : c->local_map) {
          uint8_t v = ((value >> i) & 0xff);
          temp_input.set(cm->input_args[lidx].second, v);
          i += 8;
        }
        updated = true;
        continue;
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
        for (auto const& [offset, lidx] : c->local_map) {
          uint8_t v = ((value >> i) & 0xff);
          // uint8_t v = ((value >> (t - i - 8)) & 0xff);
          temp_input.set(cm->input_args[lidx].second, v);
          i += 8;
        }
        updated = true;
      }
    }
  }
  if (updated) {
    uint64_t f_new = distance(temp_input, task);
    if (f_new < f0) {
      // std::cout << "i2s succeeded: " << f0 << " -> " << f_new << std::endl;
      input_min = temp_input;
      return f_new;
    }
  }
  return f0;
}

static uint64_t repick_start_point(MutInput &input_min, std::shared_ptr<SearchTask> task) {
  input_min.randomize();
  uint64_t ret = distance(input_min, task);
  task->orig_distances = task->distances;
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
  uint64_t ret = distance(input_min, task);
  task->orig_distances = task->distances;
  return ret;
}


bool rgd::gd_entry(std::shared_ptr<SearchTask> task) {
  MutInput input(task->inputs.size());
  MutInput scratch_input(task->inputs.size());
  //return true;

  uint64_t f0 = reload_input(input, task);
  f0 = try_i2s(input, scratch_input, f0, task);
  if (task->stopped)
    return task->solved;

  if (f0 == UINTMAX_MAX)
    return false;

  int ep_i = 0;

  Grad grad(input.len());

  while (true) {
    //std::cout << "<<< epoch=" << ep_i << " f0=" << f0 << std::endl;
    if (task->stopped) {
      break;
    }
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
  }

  return task->solved;
}
