// z3 has no cttz, ctlz or ctpop: encodings of dfsan's cttz/ctlz/ctpop ops
// (and rgd::Cttz/Ctlz/Ctpop), shared by solvers/z3-ts.cpp and
// solvers/z3-solver.cpp.
//
// Logarithmic, not one ite per bit: the kernel's find_next_bit() puts a
// __ffs() -- a cttz -- into the path at every step of a cpumask walk, and with
// a 64-deep ite chain per step set_cpu_sibling_map ran 16 seeds in 30 s
// instead of 837.  cttz/ctlz are a binary search (is the low/high half zero?
// then count it and shift it out), log2(width) ites; ctpop is the SWAR sum.
#pragma once

#include <z3++.h>

namespace symsan {

enum class BitCount { Tz, Lz, Pop };

static inline z3::expr z3_bitcount(z3::context &ctx, const z3::expr &x,
                                   BitCount kind) {
  unsigned w = x.get_sort().bv_size();
  if (kind == BitCount::Pop) {
    if (w == 8 || w == 16 || w == 32 || w == 64) {
      // pairs, nibbles, bytes, then the bytes summed by shifts (no multiply)
      auto rep = [&](uint64_t byte) {
        uint64_t v = 0;
        for (unsigned i = 0; i < w; i += 8) v |= byte << i;
        return ctx.bv_val(v, w);
      };
      z3::expr y = x - (z3::lshr(x, 1) & rep(0x55));
      y = (y & rep(0x33)) + (z3::lshr(y, 2) & rep(0x33));
      y = (y + z3::lshr(y, 4)) & rep(0x0f);
      for (unsigned s = 8; s < w; s *= 2)
        y = y + z3::lshr(y, s);
      return y & ctx.bv_val(0x7f, w);
    }
    z3::expr r = z3::zext(x.extract(0, 0), w - 1);
    for (unsigned i = 1; i < w; ++i)
      r = r + z3::zext(x.extract(i, i), w - 1);
    return r;
  }
  // the largest power of two below w: the halves the search starts with sum
  // to at least w - 1, the largest count of a non-zero x
  unsigned k = 1;
  while (k * 2 < w) k *= 2;
  z3::expr n = ctx.bv_val(0, w), y = x;
  for (; k >= 1; k /= 2) {
    z3::expr none = kind == BitCount::Tz
                        ? y.extract(k - 1, 0) == ctx.bv_val(0, k)
                        : y.extract(w - 1, w - k) == ctx.bv_val(0, k);
    n = z3::ite(none, n + ctx.bv_val(k, w), n);
    y = z3::ite(none, kind == BitCount::Tz ? z3::lshr(y, k) : z3::shl(y, k), y);
  }
  return z3::ite(x == ctx.bv_val(0, w), ctx.bv_val(w, w), n);
}

}  // namespace symsan
