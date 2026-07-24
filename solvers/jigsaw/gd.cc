#include <stdint.h>
#include <assert.h>
#include <iostream>
#include <cmath>
#include <cstring>
#include <cfloat>

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
  for (auto it : task->inputs()) {
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
  for (auto it : task->inputs()) {
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
    length = task->shapes(start);
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
    default: fprintf(stderr, "Non-relational op!\n");
  };
  return 0;
}


// Distance for an FP comparison.  The jitted function stores the two operands
// promoted to IEEE-754 double bit-patterns at a/b (see jit.cc FOeq..FUne case).
// We compute a NON-NEGATIVE double distance d that is exactly 0 iff the
// predicate holds, then map it to a uint64: for d>=0 the IEEE bit-pattern is
// monotonic in d and is 0 iff d==0 -- exactly what gradient descent needs.
// The raw bit-pattern of an O(1) distance is ~2^62, though, far larger than
// typical integer distances, so a mixed FP+integer task would be dominated (and
// sat_inc could saturate) by the FP term.  We therefore shift off the low 32
// bits (see the mapping below): this divides the scale by 2^32 -- an O(1)
// distance now maps to ~2^30 and the whole finite range stays below 2^31, so a
// single FP term no longer swamps integer distances -- while preserving both
// required properties (still monotonic in d, still 0 iff d==0) and the log-like
// wide dynamic range GD relies on.
static uint64_t fp_get_distance(uint32_t comp, uint64_t a, uint64_t b) {
  double da, db;
  memcpy(&da, &a, sizeof(da));
  memcpy(&db, &b, sizeof(db));
  bool nan = std::isnan(da) || std::isnan(db);
  double d = 0.0;
  // smallest positive double, used to keep strict predicates non-zero at the
  // boundary (a == b) -- mirrors the integer sat_inc(a-b, 1) nudge.
  const double eps = DBL_TRUE_MIN;
  switch (comp) {
    // ordered predicates: false (max distance sense) if either operand is NaN.
    case rgd::FOeq: d = nan ? (double)INFINITY : std::fabs(da - db); break;
    case rgd::FOne: d = nan ? (double)INFINITY : (da == db ? 1.0 : 0.0); break;
    case rgd::FOlt: d = (!nan && da <  db) ? 0.0 : (da - db) + eps; break;
    case rgd::FOle: d = (!nan && da <= db) ? 0.0 : (da - db) + eps; break;
    case rgd::FOgt: d = (!nan && da >  db) ? 0.0 : (db - da) + eps; break;
    case rgd::FOge: d = (!nan && da >= db) ? 0.0 : (db - da) + eps; break;
    case rgd::FOrd: d = nan ? 1.0 : 0.0; break;
    // unordered predicates: satisfied whenever either operand is NaN.
    case rgd::FUno: d = nan ? 0.0 : 1.0; break;
    case rgd::FUeq: d = nan ? 0.0 : std::fabs(da - db); break;
    case rgd::FUne: d = nan ? 0.0 : (da == db ? 1.0 : 0.0); break;
    case rgd::FUlt: d = (nan || da <  db) ? 0.0 : (da - db) + eps; break;
    case rgd::FUle: d = (nan || da <= db) ? 0.0 : (da - db) + eps; break;
    case rgd::FUgt: d = (nan || da >  db) ? 0.0 : (db - da) + eps; break;
    case rgd::FUge: d = (nan || da >= db) ? 0.0 : (db - da) + eps; break;
    default:
      fprintf(stderr, "Non-relational FP op!\n");
  }
  double m = std::fabs(d);
  uint64_t u;
  memcpy(&u, &m, sizeof(u));
  // Rescale the bit-pattern down by 2^32 (exponent bits give octave resolution,
  // the retained high mantissa bits give within-octave resolution) so the FP
  // term is comparable in scale to integer distances -- see the note above.
  u >>= 32;
  return (u == 0 && m > 0.0) ? 1 : u; // any nonzero distance stays strictly positive
}

static uint64_t get_distance(uint32_t comp, uint64_t a, uint64_t b) {
  uint64_t dis = 0;
  if (rgd::isFPRelationalKind(comp))
    return fp_get_distance(comp, a, b);
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
      fprintf(stderr, "Non-relational op!\n");
  }
  return dis;
}


static uint64_t single_distance(MutInput &input, std::vector<uint64_t> &distances, std::shared_ptr<SearchTask> task, const uint32_t index) {
  // only re-compute the distance of the constraints that are affected by the change
  uint64_t res = 0;
  for (uint32_t cons_id : task->cmap(index)) {
    auto& c = task->constraints(cons_id);
    auto& cm = task->consmetas(cons_id);
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

  for (int i = 0, n = task->size(); i < n; i++) {
    auto& c = task->constraints(i);
    auto& cm = task->consmetas(i);
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


static void partial_derivative(MutInput &orig_input, const uint32_t index, uint64_t f0, bool *sign, bool* is_linear, uint64_t *val, std::shared_ptr<SearchTask> task) {

  uint64_t orig_val = orig_input.value[index];
  uint64_t delta = 1;
  uint64_t f_plus = 0, f_minus = 0;
  uint64_t single_dis;

  // calculate f(x+delta).  The input is NOT restored between delta probes, so add
  // only the increment (delta - added) to land exactly at orig+delta rather than the
  // cumulative orig+1+4+16...  This is a clean finite difference at f(x+delta) -- as
  // the comment below intends -- at the same eval count (no extra restore/reprobe).
  uint64_t added = 0;
  for (delta = 1; delta < 256; delta = delta << 1) {
    task->plus_distances = task->min_distances;
    orig_input.update(index, true, delta - added);
    added = delta;
    single_dis = single_distance(orig_input, task->plus_distances, task, index);
    if (single_dis == 0) { // well, we got lucky and found a solution
      *sign = true;
      *is_linear = false;
      *val = 0;
      return;
    }
    f_plus = 0;
    for (int i = 0, n = task->size(); i < n; i++)
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

  // calculate f(x-delta) -- same clean-increment trick as the plus loop above
  added = 0;
  for (delta = 1; delta < 256; delta = delta << 1) {
    task->minus_distances = task->min_distances;
    orig_input.update(index, false, delta - added);
    added = delta;
    single_dis = single_distance(orig_input, task->minus_distances, task, index);
    if (single_dis == 0) { // well, we got lucky and found a solution
      *sign = false;
      *is_linear = false;
      *val = 0;
      return;
    }
    f_minus = 0;
    for (int i = 0, n = task->size(); i < n; i++)
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
  // #4: skip probing bytes that touch no currently-unsatisfied constraint. Their
  // partial derivative is definitionally 0 (f0 = sum of constraint distances; a
  // byte that only feeds already-satisfied (distance-0) constraints cannot lower
  // any term, only keep it 0 or raise it), so partial_derivative would burn ~16
  // probes just to conclude val=0. Skipping produces a bit-identical gradient
  // vector while reclaiming that budget for the MAX_EXEC_TIMES-capped search.
  uint64_t max = 0;
  uint32_t index = 0;
  for (auto &gradu : grad.get_value()) {

    if (task->stopped) {
      break;
    }
    bool sign = false;
    bool is_linear = false;
    uint64_t val = 0;

    bool relevant = false;
    for (size_t cons_id : task->cmap(index)) {
      if (task->min_distances[cons_id]) { relevant = true; break; }
    }
    if (!relevant) {
      gradu.sign = false;
      gradu.val = 0;
      index++;
      continue;
    }

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
        for (int i = 0, n = task->size(); i < n; i++)
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
        // #5: the doubling line search jumped from the last-accepted point
        // (== input_min, f_last) straight to a worse point at `step`, stepping
        // over a possible minimum in between. Instead of abandoning it, bisect a
        // few times back toward input_min along the same gradient to recover a
        // better point before falling through to coordinate descent.
        if (step > 1) {
          size_t bstep = step >> 1;
          for (int bt = 0; bt < BACKTRACK_MAX && bstep >= 1; bt++) {
            if (task->stopped)
              break;
            input = input_min;
            uint64_t fb = 0;
            if (doDelta) {
              double movement = grad.get_value()[deltaIdx].pct * (double)bstep;
              input.update(deltaIdx, grad.get_value()[deltaIdx].sign, (uint64_t)movement);
              single_distance(input, task->distances, task, deltaIdx);
              for (int i = 0, n = task->size(); i < n; i++)
                fb = sat_inc(fb, task->distances[i]);
              task->attempts += 1;
              if (task->attempts > MAX_EXEC_TIMES)
                task->stopped = true;
            } else {
              compute_delta_all(input, grad, bstep);
              fb = distance(input, task->distances, task);
            }
            if (fb == 0) {
              task->stopped = true;
              task->solved = true;
              add_results(input, task);
              return 0;
            }
            if (fb < f_last) {
              input_min = input;
              task->min_distances = task->distances;
              f_last = fb;
              break; // recovered a better point; stop bisecting
            }
            bstep >>= 1;
          }
          // restore best-known state for the next coordinate phase
          input = input_min;
          task->distances = task->min_distances;
        }
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
      if (rhs) return v - 1;
      else return v + 1;
    case rgd::Ult:
    case rgd::Slt:
      if (rhs) return v + 1;
      else return v - 1;
    default:
      fprintf(stderr, "Non-relational op!\n");
  }
  return v;
}


// FP analogue of get_i2s_value.  v is the CONSTANT operand's value; rhs==true
// means the input is the LEFT operand (op1) and v is op2, rhs==false means the
// input is the RIGHT operand (op2) and v is op1.  Returns the value to assign to
// the input side so that (op1 <comp> op2) holds.  Strict inequalities nudge by
// one ULP in the correct precision (nextafterf for float) toward the satisfying
// side; the caller VERIFIES via fp_get_distance == 0, so a wrong guess is simply
// rejected.  FOrd/FUno depend on NaN-ness (not i2s-able) -> return v (rejected).
static double get_i2s_fp_value(uint32_t comp, double v, bool rhs, bool is_float) {
  auto up = [&](double x) {
    return is_float ? (double)std::nextafterf((float)x, INFINITY)
                    : std::nextafter(x, INFINITY);
  };
  auto down = [&](double x) {
    return is_float ? (double)std::nextafterf((float)x, -INFINITY)
                    : std::nextafter(x, -INFINITY);
  };
  switch (comp) {
    case rgd::FOeq: case rgd::FUeq:
    case rgd::FOle: case rgd::FUle: // op1<=op2 satisfied by equality
    case rgd::FOge: case rgd::FUge: // op1>=op2 satisfied by equality
      return v;
    case rgd::FOlt: case rgd::FUlt: // op1 < op2
      return rhs ? down(v)   // input=op1 -> just below op2
                 : up(v);    // input=op2 -> just above op1
    case rgd::FOgt: case rgd::FUgt: // op1 > op2
      return rhs ? up(v)     // input=op1 -> just above op2
                 : down(v);  // input=op2 -> just below op1
    case rgd::FOne: case rgd::FUne: // op1 != op2
      return up(v);
    default:
      return v;
  }
}


static uint64_t try_new_i2s_value(std::shared_ptr<const Constraint> const& c, uint32_t comparison, uint64_t value, std::shared_ptr<SearchTask> task) {
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


// FP variant of try_new_i2s_value.  Unlike the integer helper (which writes the
// candidate's `value` across the whole local_map -- fine only for single-chunk
// constraints), this seeds EVERY arg from the current input and overrides just
// the candidate's `size` bytes, so other symbolic operands (e.g. y in x==y+1.0)
// keep their current values instead of being clobbered.
static uint64_t try_new_i2s_fp_value(std::shared_ptr<const Constraint> const& c,
    std::unique_ptr<ConsMeta> const& cm, MutInput &input_min, uint32_t comparison,
    size_t offset, uint32_t size, uint64_t value, std::shared_ptr<SearchTask> task) {
  int arg_idx = 0;
  for (auto const& arg : cm->input_args) {
    if (arg.first) // symbolic: keep the current input value
      task->scratch_args[RET_OFFSET + arg_idx] = input_min.get(arg.second);
    else
      task->scratch_args[RET_OFFSET + arg_idx] = arg.second;
    ++arg_idx;
  }
  // override only the candidate bytes with the target value
  int i = 0;
  for (size_t off = offset; off < offset + size; off++) {
    const uint32_t lidx = c->local_map.at(off);
    task->scratch_args[RET_OFFSET + lidx] = ((value >> i) & 0xff);
    i += 8;
  }
  c->fn(task->scratch_args);
  return get_distance(comparison, task->scratch_args[0], task->scratch_args[1]);
}


static uint64_t try_i2s(MutInput &input_min, MutInput &temp_input, uint64_t f0, std::shared_ptr<SearchTask> task) {
  // Iterate the input-to-state pass to a (bounded) fixpoint.  A single snap can
  // turn a previously-satisfied coupled equality unsatisfied -- e.g. snapping X to
  // a constant to satisfy `X == C` breaks `X == assemble(bytes)` by exactly the same
  // amount, leaving the global distance unchanged (a lateral move).  The strict
  // improvement gate alone would revert such a move and deadlock, so we ALSO accept
  // lateral (equal-f) snaps that shift WHICH constraints are satisfied; a later round
  // then snaps the now-unsatisfied side (the assembly bytes) to a strict improvement.
  // Bounded by I2S_MAX_ROUNDS so any lateral cycle terminates.
  for (int round = 0; round < I2S_MAX_ROUNDS; round++) {
  temp_input = input_min;
  bool updated = false;
  for (int k = 0; k < task->size(); k++) {
    auto& c = task->constraints(k);
    auto& cm = task->consmetas(k);
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
      } else if (rgd::isFPRelationalKind(cm->comparison)) {
        // FP input-to-state.  The jitted fn stores both compare operands as
        // IEEE-754 *double* bit-patterns (see jit.cc), so detect a candidate
        // input chunk whose FP value equals one operand, then snap it to the
        // value that satisfies the predicate against the other (constant)
        // operand.  This lets jigsaw hit exact FP equalities (e.g. x == y with
        // two symbolic operands, or x == C) that gradient descent alone cannot.
        double op1d, op2d;
        memcpy(&op1d, &cm->op1, sizeof(op1d));
        memcpy(&op2d, &cm->op2, sizeof(op2d));
        bool fp_done = false;
        for (auto const& candidate : cm->i2s_candidates) {
          const size_t c_off = candidate.first;
          const uint32_t c_size = candidate.second;
          // A candidate is a maximal run of *consecutive* symbolic input bytes,
          // so two adjacent FP operands (e.g. x@0 and y@8 in `x == y + 1.0`)
          // merge into one oversized run.  Rather than require the whole run to
          // be exactly a float/double, slide an FP-sized window across it and
          // test each position: reassemble the window's raw bytes, match its FP
          // value against a stored operand, and snap it to satisfy the predicate
          // against the other operand.  try_new_i2s_fp_value VERIFIES every
          // guess (fp_get_distance == 0), so windows that don't line up with a
          // real operand are simply rejected.  This lets jigsaw hit exact FP
          // equalities (e.g. x == y with two symbolic operands, or x == C) that
          // gradient descent alone cannot.
          for (uint32_t fpsize : {(uint32_t)8, (uint32_t)4}) {
            if (c_size < fpsize) continue;
            const bool is_float = (fpsize == 4);
            for (size_t offset = c_off; offset + fpsize <= c_off + c_size; offset++) {
              // reassemble the raw input bytes of this window
              uint64_t input = 0;
              int i = 0;
              for (size_t off = offset; off < offset + fpsize; off++) {
                const uint32_t lidx = c->local_map.at(off);
                uint64_t v = input_min.get(cm->input_args[lidx].second);
                input |= (v << i);
                i += 8;
              }
              // interpret the chunk as an FP number, promoted to double so it can
              // be matched against the (always double) stored operands
              double cur;
              if (is_float) { float f; memcpy(&f, &input, sizeof(f)); cur = (double)f; }
              else { memcpy(&cur, &input, sizeof(cur)); }
              uint64_t cur_bits;
              memcpy(&cur_bits, &cur, sizeof(cur_bits));

              double target;
              if (cur_bits == cm->op1) {
                target = get_i2s_fp_value(cm->comparison, op2d, true, is_float);
              } else if (cur_bits == cm->op2) {
                target = get_i2s_fp_value(cm->comparison, op1d, false, is_float);
              } else {
                continue;
              }

              // encode the target in the input's native FP width
              uint64_t value = 0;
              if (is_float) { float tf = (float)target; memcpy(&value, &tf, sizeof(tf)); }
              else { memcpy(&value, &target, sizeof(target)); }

              // test the new value (verifies via fp_get_distance == 0)
              uint64_t dis = try_new_i2s_fp_value(c, cm, input_min, cm->comparison,
                                                  offset, fpsize, value, task);
              if (dis == 0) {
                i = 0;
                for (size_t off = offset; off < offset + fpsize; off++) {
                  const uint32_t lidx = c->local_map.at(off);
                  uint8_t v = ((value >> i) & 0xff);
                  temp_input.set(cm->input_args[lidx].second, v);
                  i += 8;
                }
                updated = true;
                fp_done = true;
                break; // one match per comparison
              }
            } // end foreach window position
            if (fp_done) break;
          } // end foreach fp width
          if (fp_done) break;
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
        if (cm->i2s_candidates.size() != 1) {
          fprintf(stderr, "memcmp should have only one candidate\n");
          continue;
        }
        size_t offset = cm->i2s_candidates[0].first;
        uint32_t size = cm->i2s_candidates[0].second;
        if (size != c->local_map.size()) {
          fprintf(stderr, "input size mismatch\n");
          continue;
        }
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
  if (!updated) break; // no snap applied this round -> fixpoint
  uint64_t f_new = distance(temp_input, task->distances, task);
  if (f_new < f0) {
    // std::cout << "i2s succeeded: " << f0 << " -> " << f_new << std::endl;
    input_min = temp_input;
    task->min_distances = task->distances;
    f0 = f_new;
    if (f0 == 0) break; // solved
    continue;           // strict progress; look for more snaps
  }
  if (f_new == f0) {
    // Lateral move: total distance unchanged.  Keep it only if it actually shifted
    // which constraints are satisfied (min_distances != distances), so that the next
    // round has a newly-unsatisfied constraint to snap.  Otherwise stop -- committing
    // a no-op would just spin until the round cap.
    if (task->min_distances == task->distances) break;
    input_min = temp_input;
    task->min_distances = task->distances;
    continue;
  }
  break; // f_new > f0: the snap worsened the global distance, discard it
  } // end round loop
  return f0;
}

static uint64_t repick_start_point(MutInput &input_min, std::shared_ptr<SearchTask> task) {
  input_min.randomize();
  uint64_t ret = distance(input_min, task->min_distances, task);
  return ret;
}


static uint64_t reload_input(MutInput &input_min, std::shared_ptr<SearchTask> task) {
  input_min.assign(task->inputs());
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
  // JIGSAW_DEBUG=1 traces which phase produced the solution (i2s vs gradient
  // descent) and the attempt count -- useful for telling apart constraints that
  // are actually *searched* from those the i2s heuristic snaps for free.
  static const bool dbg = (getenv("JIGSAW_DEBUG") != nullptr);
  MutInput input(task->inputs_size());
  MutInput scratch_input(task->inputs_size());
  task->attempts = 0;

  uint64_t f0 = reload_input(input, task);
  f0 = try_i2s(input, scratch_input, f0, task);
  if (task->stopped) {
    if (dbg)
      fprintf(stderr, "[jigsaw] solved=%d by i2s (initial), attempts=%lu\n",
              task->solved, (unsigned long)task->attempts);
    return task->solved;
  }

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
      if (task->stopped) {
        if (dbg)
          fprintf(stderr, "[jigsaw] solved=%d by i2s (restart), attempts=%lu\n",
                  task->solved, (unsigned long)task->attempts);
        break;
      }
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
    if (dbg && task->solved)
      fprintf(stderr, "[jigsaw] solved=1 by gradient descent, epoch=%d attempts=%lu\n",
              ep_i, (unsigned long)task->attempts);
    ep_i += 1;
    //if (ep_i == 2) break;
  }

  if (dbg && !task->solved)
    fprintf(stderr, "[jigsaw] gave up (unsolved), epochs=%d attempts=%lu\n",
            ep_i, (unsigned long)task->attempts);
  return task->solved;
}
