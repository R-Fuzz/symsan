#include "solver.h"

extern "C" {
#include "afl-fuzz.h"
}

using namespace rgd;

#define SWAP16(_x)                    \
  ({                                  \
                                      \
    u16 _ret = (_x);                  \
    (u16)((_ret << 8) | (_ret >> 8)); \
                                      \
  })

#define SWAP32(_x)                                                   \
  ({                                                                 \
                                                                     \
    u32 _ret = (_x);                                                 \
    (u32)((_ret << 24) | (_ret >> 24) | ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00));                               \
                                                                     \
  })

#define SWAP64(_x)                                                             \
  ({                                                                           \
                                                                               \
    u64 _ret = (_x);                                                           \
    _ret =                                                                     \
        (_ret & 0x00000000FFFFFFFF) << 32 | (_ret & 0xFFFFFFFF00000000) >> 32; \
    _ret =                                                                     \
        (_ret & 0x0000FFFF0000FFFF) << 16 | (_ret & 0xFFFF0000FFFF0000) >> 16; \
    _ret =                                                                     \
        (_ret & 0x00FF00FF00FF00FF) << 8 | (_ret & 0xFF00FF00FF00FF00) >> 8;   \
    _ret;                                                                      \
                                                                               \
  })

// It is impossible to define 128 bit constants, so ...
#ifdef WORD_SIZE_64
  #define SWAPN(_x, _l)                            \
    ({                                             \
                                                   \
      u128  _res = (_x), _ret;                     \
      char *d = (char *)&_ret, *s = (char *)&_res; \
      int   i;                                     \
      for (i = 0; i < 16; i++)                     \
        d[15 - i] = s[i];                          \
      u32 sr = 128U - ((_l) << 3U);                \
      (_ret >>= sr);                               \
      (u128) _ret;                                 \
                                                   \
    })
#endif

#define SWAPNN(_x, _y, _l)                     \
  ({                                           \
                                               \
    char *d = (char *)(_x), *s = (char *)(_y); \
    u32   i, l = (_l)-1;                       \
    for (i = 0; i <= l; i++)                   \
      d[l - i] = s[i];                         \
                                               \
  })

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

I2SSolver::I2SSolver(): matches(0), mismatches(0) {}

solver_result_t
I2SSolver::solve(std::shared_ptr<SearchTask> task,
                 const uint8_t *in_buf, size_t in_size,
                 uint8_t *out_buf, size_t &out_size) {

  if (task->constraints.size() > 1) {
    // FIXME: only support single constraint for now
    return SOLVER_TIMEOUT;
  }
  auto const& c = task->constraints[0];
  auto comparison = task->comparisons[0];
  if (likely(isRelationalKind(comparison))) {
    size_t last_offset = -1;
    uint64_t value = 0, value_r = 0;
    uint64_t r = 0;
    int i = 0;
    for (const auto& [offset, lidx] : c->local_map) {
      uint32_t s = c->shapes.at(offset);
      if (s > 1) {
        switch(s) {
          case 2:
            value = *(uint16_t*)&in_buf[offset];
            value_r = SWAP16(value);
            break;
          case 4:
            value = *(uint32_t*)&in_buf[offset];
            value_r = SWAP32(value);
            break;
          case 8:
            value = *(uint64_t*)&in_buf[offset];
            value_r = SWAP64(value);
            break;
          default:
            assert(false && "unsupported shape");
        }
        if (c->op1 == value) {
          matches++;
          r = get_i2s_value(comparison, c->op2, false);
        } else if (c->op2 == value) {
          matches++;
          r = get_i2s_value(comparison, c->op1, true);
        } else if (c->op1 == value_r) {
          matches++;
          r = get_i2s_value(comparison, c->op2, false);
          r = SWAP64(r) >> (64 - s * 8);
        } else if (c->op2 == value_r) {
          matches++;
          r = get_i2s_value(comparison, c->op1, true);
          r = SWAP64(r) >> (64 - s * 8);
        } else {
          value = 0;
          i = 0;
          last_offset = offset;
          continue; // next offset
        }
        DEBUGF("i2s: %lu = %lx\n", offset, r);
        memcpy(out_buf, in_buf, in_size);
        out_size = in_size;
        memcpy(&out_buf[offset], &r, s);
        return SOLVER_SAT;
      } else { // s == 1
        // check individual bytes
        if (i == 0) {
          last_offset = offset;
        } else {
          if (last_offset + 1 != offset) {
            // starting a new sequence of byte(s)
            // check if the previous sequence is a match
            value_r = SWAP64(value) >> (64 - i * 8);
            if (c->op1 == value) {
              matches++;
              r = get_i2s_value(comparison, c->op2, false);
            } else if (c->op2 == value) {
              matches++;
              r = get_i2s_value(comparison, c->op1, true);
            } else if (c->op1 == value_r) {
              matches++;
              r = get_i2s_value(comparison, c->op2, false);
              r = SWAP64(r) >> (64 - i * 8);
            } else if (c->op2 == value_r) {
              matches++;
              r = get_i2s_value(comparison, c->op1, true);
              r = SWAP64(r) >> (64 - i * 8);
            } else {
              value = 0;
              i = 0;
              last_offset = offset;
              continue; // next offset
            }
            DEBUGF("i2s: %lu = %lx\n", last_offset, r);
            memcpy(out_buf, in_buf, in_size);
            out_size = in_size;
            memcpy(&out_buf[offset], &r, i);
            return SOLVER_SAT;
          } else {
            // match, do nothing
          }
        }
        value |= in_buf[offset] << (i * 8);
        i++;
      }
    }
    // check the last sequence
    value_r = SWAP64(value) >> (64 - i * 8);
    if (c->op1 == value) {
      matches++;
      r = get_i2s_value(comparison, c->op2, false);
    } else if (c->op2 == value) {
      matches++;
      r = get_i2s_value(comparison, c->op1, true);
    } else if (c->op1 == value_r) {
      matches++;
      r = get_i2s_value(comparison, c->op2, false);
      r = SWAP64(r) >> (64 - i * 8);
    } else if (c->op2 == value_r) {
      matches++;
      r = get_i2s_value(comparison, c->op1, true);
      r = SWAP64(r) >> (64 - i * 8);
    } else {
      mismatches++;
      return SOLVER_TIMEOUT;
    }
    DEBUGF("i2s: %lu = %lx\n", last_offset, r);
    memcpy(out_buf, in_buf, in_size);
    out_size = in_size;
    memcpy(&out_buf[last_offset], &r, i);
    return SOLVER_SAT;
  } else if (comparison == rgd::Memcmp) {
    DEBUGF("i2s: try memcmp\n");
    memcpy(out_buf, in_buf, in_size);
    auto const& cm = task->consmeta[0];
    size_t const_index = 0;
    for (auto const& arg : c->input_args) {
      if (!arg.first) break; // first constant arg
      const_index++;
    }
    int i = 0;
    uint64_t value = 0;
    for (auto const& [offset, lidx] : c->local_map) {
      if (i == 0)
        value = c->input_args[const_index].second;
      uint8_t v = ((value >> i) & 0xff);
      out_buf[offset] = v;
      DEBUGF("  %lu = %u\n", offset, v);
      i += 8;
      if (i == 64) {
        const_index++; // move on to the next 64-bit chunk
        i = 0;
      }
    }
    out_size = in_size;
    return SOLVER_SAT;
  }
  mismatches++;
  return SOLVER_TIMEOUT;
}