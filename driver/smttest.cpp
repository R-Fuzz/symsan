// Standalone SMT-LIB2 front-end for the RGD jigsaw (JIT + gradient-descent) solver.
//
// SymSan's jigsaw solver is normally fed by the concolic engine: the runtime
// records a dataflow graph, parsers/rgd-parser.cpp lifts it into rgd::AstNode /
// rgd::SearchTask, and solvers/jit-solver.cpp JITs each constraint and runs
// gradient descent (solvers/jigsaw/gd.cc).  This driver bypasses the runtime and
// builds the very same SearchTask directly from an SMT-LIB2 file, so jigsaw can be
// exercised as a standalone solver.
//
// Jigsaw is an INCOMPLETE local-search solver: it can find a model for a
// satisfiable conjunction of constraints (gradient descent drives every
// constraint's distance to 0), but it can NEVER prove unsatisfiability and it
// rejects boolean structure it cannot turn into a conjunction of comparisons.
// This driver is therefore honest about its limits:
//   - it prints "sat" + a model only when a sound solver returns SOLVER_SAT;
//   - it prints "unknown" for everything else (timeout, unsupported input, or a
//     genuinely unsatisfiable instance -- we cannot tell these apart).
// It never prints "unsat".
//
// Supported fragment (QF_BV / QF_FP / QF_BVFP satisfiable subset):
//   - sorts: (_ BitVec N), (_ FloatingPoint 8 24)=Float32, (_ FloatingPoint 11 53)
//     =Float64 (and the Float32/Float64 aliases);
//   - commands: set-*/declare-const/declare-fun/define-fun (0-arg)/assert/
//     check-sat/get-model/exit;
//   - assertions: a comparison, (and ...) of comparisons, (not <comparison>), and
//     let-bindings; anything else (or / => / xor / ite / nested boolean) makes the
//     whole query "unknown";
//   - BV ops: bvadd/sub/mul/udiv/sdiv/urem/srem/neg/not/and/or/xor/shl/lshr/ashr,
//     concat, (_ extract i j), (_ zero_extend k), (_ sign_extend k);
//   - FP ops: fp.add/sub/mul/div/rem/neg/abs/sqrt/min/max/roundToIntegral;
//   - predicates: = distinct bvult bvule bvugt bvuge bvslt bvsle bvsgt bvsge
//     fp.eq fp.lt fp.leq fp.gt fp.geq (= on FP sorts is bitwise equality).
//
// Usage: smttest [--z3] [--no-jigsaw] [--time] file.smt2
//   --z3          also try the (complete, FP-aware) z3 solver after jigsaw
//   --no-jigsaw   skip jigsaw (useful with --z3 as a reference oracle)
//   --time        print a "TIME parse=.. codegen=.. jit=.. gd=.. solve=.. total=.."
//                 line (microseconds) to stderr; codegen/jit/gd are the jigsaw-
//                 internal split of solve.
// Env SMT_USE_Z3 / SMT_NO_JIGSAW / SMT_TIME mirror the flags.

#include "ast.h"
#include "task.h"
#include "solver.h"

#include "dfsan/dfsan.h"

#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace rgd;

#define DEBUG 0
#if DEBUG
#define DBG(...) do { fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define DBG(...) do { } while (0)
#endif

// The i2s solver (part of librgd-solver) references the global
// __dfsan::get_label_info.  This driver never runs i2s (jigsaw builds its AST
// directly from SMT-LIB2, not from a union table), but the symbol must resolve
// for the link to succeed; provide a stub that fails loudly if ever reached.
namespace __dfsan {
dfsan_label_info* get_label_info(dfsan_label label) {
  (void)label;
  throw std::runtime_error("get_label_info is not available in smttest");
}
} // namespace __dfsan

namespace {

// -------------------------------------------------------------------------
// S-expression reader
// -------------------------------------------------------------------------

struct SExpr {
  bool is_atom = false;
  std::string atom;
  std::vector<SExpr> list;
};

// thrown for any construct outside the supported fragment; caught at the top and
// turned into an "unknown" result.
struct Unsupported {
  std::string msg;
};

struct ParseError {
  std::string msg;
};

class SexpReader {
public:
  explicit SexpReader(const std::string &s) : s_(s) {}

  bool eof() {
    skip_ws();
    return pos_ >= s_.size();
  }

  SExpr read() {
    skip_ws();
    if (pos_ >= s_.size()) throw ParseError{"unexpected end of input"};
    char c = s_[pos_];
    if (c == '(') {
      ++pos_;
      SExpr e;
      e.is_atom = false;
      while (true) {
        skip_ws();
        if (pos_ >= s_.size()) throw ParseError{"unterminated list"};
        if (s_[pos_] == ')') { ++pos_; break; }
        e.list.push_back(read());
      }
      return e;
    } else if (c == ')') {
      throw ParseError{"unexpected ')'"};
    } else if (c == '|') {
      // quoted symbol: everything up to the matching '|'
      size_t start = ++pos_;
      while (pos_ < s_.size() && s_[pos_] != '|') ++pos_;
      if (pos_ >= s_.size()) throw ParseError{"unterminated | symbol"};
      SExpr e;
      e.is_atom = true;
      e.atom = s_.substr(start, pos_ - start);
      ++pos_; // consume closing '|'
      return e;
    } else {
      size_t start = pos_;
      while (pos_ < s_.size()) {
        char d = s_[pos_];
        if (std::isspace((unsigned char)d) || d == '(' || d == ')' || d == ';')
          break;
        ++pos_;
      }
      SExpr e;
      e.is_atom = true;
      e.atom = s_.substr(start, pos_ - start);
      return e;
    }
  }

private:
  void skip_ws() {
    while (pos_ < s_.size()) {
      char c = s_[pos_];
      if (c == ';') { // line comment
        while (pos_ < s_.size() && s_[pos_] != '\n') ++pos_;
      } else if (std::isspace((unsigned char)c)) {
        ++pos_;
      } else {
        break;
      }
    }
  }

  const std::string &s_;
  size_t pos_ = 0;
};

// -------------------------------------------------------------------------
// numeric-literal helpers
// -------------------------------------------------------------------------

// parse a #x.. / #b.. bit-vector literal into (value, width_bits).  Values wider
// than 64 bits are rejected (the jigsaw input array stores one uint64 per slot).
static bool parse_bits_literal(const std::string &tok, uint64_t &value,
                               uint32_t &width) {
  if (tok.size() < 3 || tok[0] != '#') return false;
  if (tok[1] == 'x') {
    width = (uint32_t)(tok.size() - 2) * 4;
    if (width > 64) throw Unsupported{"bit-vector literal wider than 64 bits"};
    value = 0;
    for (size_t i = 2; i < tok.size(); ++i) {
      char c = tok[i];
      uint64_t d;
      if (c >= '0' && c <= '9') d = c - '0';
      else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
      else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
      else throw ParseError{"bad hex literal " + tok};
      value = (value << 4) | d;
    }
    return true;
  } else if (tok[1] == 'b') {
    width = (uint32_t)(tok.size() - 2);
    if (width > 64) throw Unsupported{"bit-vector literal wider than 64 bits"};
    value = 0;
    for (size_t i = 2; i < tok.size(); ++i) {
      char c = tok[i];
      if (c != '0' && c != '1') throw ParseError{"bad binary literal " + tok};
      value = (value << 1) | (uint64_t)(c - '0');
    }
    return true;
  }
  return false;
}

static bool parse_uint(const std::string &tok, uint64_t &out) {
  if (tok.empty()) return false;
  uint64_t v = 0;
  for (char c : tok) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + (uint64_t)(c - '0');
  }
  out = v;
  return true;
}

// reinterpret a double/float as its IEEE-754 bit pattern of the given width.
static uint64_t fp_to_bits(double d, uint32_t width) {
  if (width == 32) {
    float f = (float)d;
    uint32_t u;
    std::memcpy(&u, &f, sizeof(u));
    return u;
  }
  uint64_t u;
  std::memcpy(&u, &d, sizeof(u));
  return u;
}

// -------------------------------------------------------------------------
// SMT-LIB2 -> RGD SearchTask translator
// -------------------------------------------------------------------------

struct VarInfo {
  uint32_t offset;   // byte offset in the virtual input buffer
  uint32_t bits;     // declared width
  bool is_fp;
};

struct TermInfo {
  uint16_t bits;
  bool is_fp;
};

using Env = std::map<std::string, const SExpr *>;

// A boolean formula is normalized to DNF: a disjunction of clauses, where each
// clause is a conjunction of relational Literals.  This mirrors the RGD parser's
// to_nnf + to_dnf pipeline (parsers/rgd-parser.cpp): negations are pushed to the
// comparison leaves (carried in Literal::negate) and every disjunction becomes a
// separate clause, i.e. a separate SearchTask.  The formula is SAT iff ANY clause
// (task) is SAT; UNSAT iff EVERY clause is proven UNSAT.
struct Literal {
  const SExpr *e;  // the relational sub-expression (a comparison)
  bool negate;     // whether this occurrence is negated
  Env env;         // let-binding environment active at this occurrence
};
using Clause = std::vector<Literal>;   // conjunction of literals
using Formula = std::vector<Clause>;   // disjunction of clauses (DNF)

// Guard against DNF blow-up from many conjoined disjunctions (cartesian product).
static constexpr size_t MAX_CLAUSES = 4096;

class Translator {
public:
  std::map<std::string, VarInfo> vars;
  std::vector<std::string> var_order;   // declaration order, for model printing
  std::map<std::string, SExpr> defines; // 0-arg define-fun bodies
  std::map<std::string, SExpr> sort_defines; // 0-arg define-sort aliases
  uint32_t total_bytes = 0;

  task_t task = std::make_shared<SearchTask>();
  // running DNF of the conjunction of all assertions; starts as {{}} == true.
  Formula pending_ = Formula{Clause{}};
  std::vector<task_t> tasks;  // one SearchTask per DNF clause (built at the end)
  bool trivial_sat = false;   // an empty clause appeared: unconditionally SAT

  // process a top-level command; returns false to stop (exit)
  void run_command(const SExpr &cmd) {
    if (cmd.is_atom || cmd.list.empty() || !cmd.list[0].is_atom)
      throw ParseError{"malformed command"};
    const std::string &head = cmd.list[0].atom;
    if (head == "declare-const") {
      // (declare-const name sort)
      if (cmd.list.size() != 3) throw ParseError{"bad declare-const"};
      declare_var(cmd.list[1].atom, cmd.list[2]);
    } else if (head == "declare-fun") {
      // (declare-fun name () sort)
      if (cmd.list.size() != 4) throw ParseError{"bad declare-fun"};
      if (!cmd.list[2].is_atom && !cmd.list[2].list.empty())
        throw Unsupported{"uninterpreted function with arguments"};
      declare_var(cmd.list[1].atom, cmd.list[3]);
    } else if (head == "define-fun") {
      // (define-fun name () sort body) -- only 0-arg macros are supported
      if (cmd.list.size() != 5) throw ParseError{"bad define-fun"};
      if (!(cmd.list[2].is_atom) && !cmd.list[2].list.empty())
        throw Unsupported{"define-fun with arguments"};
      defines[cmd.list[1].atom] = cmd.list[4];
    } else if (head == "define-sort") {
      // (define-sort name () sort) -- only 0-arg sort aliases are supported
      if (cmd.list.size() != 4) throw ParseError{"bad define-sort"};
      if (!(cmd.list[2].is_atom) && !cmd.list[2].list.empty())
        throw Unsupported{"define-sort with parameters"};
      sort_defines[cmd.list[1].atom] = cmd.list[3];
    } else if (head == "assert") {
      if (cmd.list.size() != 2) throw ParseError{"bad assert"};
      Env env;
      // Normalize the assertion to DNF and conjoin it with the running formula.
      Formula f = to_dnf(cmd.list[1], env, /*negate=*/false);
      pending_ = and_formula(pending_, f);
    }
    // set-logic / set-info / set-option / check-sat / get-model / exit / push /
    // pop are all no-ops here: we solve once, after reading the whole file.
  }

  // Build one SearchTask per DNF clause from the accumulated formula.  Sets
  // trivial_sat if some clause is empty (unconditionally true).  Populates
  // `tasks` with the finalized, non-trivial tasks.  Returns false if there is
  // nothing to solve (no clauses at all, or everything trivial).
  bool build_tasks() {
    if (pending_.empty()) return false; // formula reduced to false
    for (const auto &clause : pending_) {
      if (clause.empty()) { trivial_sat = true; continue; } // true disjunct
      task = std::make_shared<SearchTask>();
      for (const auto &lit : clause)
        emit_comparison(*lit.e, lit.env, lit.negate);
      if (task->empty()) { trivial_sat = true; continue; }
      task->finalize();
      tasks.push_back(task);
    }
    return trivial_sat || !tasks.empty();
  }

private:
  // ---- declarations ------------------------------------------------------

  void declare_var(const std::string &name, const SExpr &sort) {
    uint32_t bits;
    bool is_fp;
    parse_sort(sort, bits, is_fp);
    VarInfo vi;
    vi.offset = total_bytes;
    vi.bits = bits;
    vi.is_fp = is_fp;
    vars[name] = vi;
    var_order.push_back(name);
    total_bytes += (bits + 7) / 8;
    DBG("declare %s @%u bits=%u fp=%d\n", name.c_str(), vi.offset, bits, is_fp);
  }

  void parse_sort(const SExpr &sort, uint32_t &bits, bool &is_fp) {
    if (sort.is_atom) {
      if (sort.atom == "Float32") { bits = 32; is_fp = true; return; }
      if (sort.atom == "Float64") { bits = 64; is_fp = true; return; }
      if (sort.atom == "RoundingMode")
        throw Unsupported{"RoundingMode sort"};
      // resolve a 0-arg define-sort alias, then re-parse the aliased sort
      auto it = sort_defines.find(sort.atom);
      if (it != sort_defines.end()) { parse_sort(it->second, bits, is_fp); return; }
      throw Unsupported{"sort " + sort.atom};
    }
    if (sort.list.size() >= 1 && sort.list[0].is_atom && sort.list[0].atom == "_") {
      const std::string &k = sort.list[1].atom;
      if (k == "BitVec") {
        uint64_t n;
        if (!parse_uint(sort.list[2].atom, n)) throw ParseError{"bad BitVec width"};
        bits = (uint32_t)n;
        is_fp = false;
        return;
      }
      if (k == "FloatingPoint") {
        uint64_t eb, sb;
        if (!parse_uint(sort.list[2].atom, eb) || !parse_uint(sort.list[3].atom, sb))
          throw ParseError{"bad FloatingPoint sort"};
        if (eb == 8 && sb == 24) { bits = 32; is_fp = true; return; }
        if (eb == 11 && sb == 53) { bits = 64; is_fp = true; return; }
        throw Unsupported{"FloatingPoint width other than 32/64"};
      }
    }
    throw Unsupported{"compound sort"};
  }

  // ---- assertion (boolean) layer ----------------------------------------

  // Resolve let/define atom substitutions, following the environment.
  const SExpr *resolve(const SExpr *e, const Env &env) {
    while (e->is_atom) {
      auto it = env.find(e->atom);
      if (it != env.end()) { e = it->second; continue; }
      auto d = defines.find(e->atom);
      if (d != defines.end()) { e = &d->second; continue; }
      break;
    }
    return e;
  }

  Env bind_let(const SExpr &lets, const Env &env) {
    // (let ((a e1) (b e2) ...) body) -- bindings are simultaneous in SMT-LIB,
    // but since we only substitute names to sub-expressions (no evaluation),
    // extending a copy of the parent env is sufficient.
    Env e2 = env;
    for (const auto &b : lets.list) {
      if (b.list.size() != 2 || !b.list[0].is_atom) throw ParseError{"bad let binding"};
      e2[b.list[0].atom] = &b.list[1];
    }
    return e2;
  }

  // Conjoin two DNF formulas: (A) AND (B) distributes into the cross product of
  // their clauses (mirrors to_dnf's LAnd case in rgd-parser.cpp).
  Formula and_formula(const Formula &a, const Formula &b) {
    Formula out;
    for (const auto &ca : a) {
      for (const auto &cb : b) {
        Clause c;
        c.reserve(ca.size() + cb.size());
        c.insert(c.end(), ca.begin(), ca.end());
        c.insert(c.end(), cb.begin(), cb.end());
        out.push_back(std::move(c));
        if (out.size() > MAX_CLAUSES) throw Unsupported{"DNF too large"};
      }
    }
    return out;
  }

  // Normalize a boolean expression to DNF, pushing negation to the leaves (NNF)
  // as we go (the `negate` flag).  Boolean connectives and/or/not/=>/xor/ite are
  // expanded; everything else is a relational leaf captured as a Literal.  This
  // is the S-expression analogue of RGDAstParser::to_nnf + to_dnf.
  Formula to_dnf(const SExpr &e0, const Env &env, bool negate) {
    const SExpr *ep = resolve(&e0, env);
    const SExpr &e = *ep;

    if (e.is_atom) {
      if (e.atom == "true")
        return negate ? Formula{} : Formula{Clause{}};
      if (e.atom == "false")
        return negate ? Formula{Clause{}} : Formula{};
      // a bare (0-arg) boolean symbol we can't interpret as a comparison
      throw Unsupported{"boolean variable " + e.atom};
    }
    if (e.list.empty() || !e.list[0].is_atom)
      throw Unsupported{"boolean application"};
    const std::string &op = e.list[0].atom;

    if (op == "not") {
      if (e.list.size() != 2) throw ParseError{"bad not"};
      return to_dnf(e.list[1], env, !negate);
    }
    if (op == "let") {
      if (e.list.size() != 3) throw ParseError{"bad let"};
      Env e2 = bind_let(e.list[1], env);
      return to_dnf(e.list[2], e2, negate);
    }
    if (op == "and" || op == "or") {
      if (e.list.size() < 2) throw ParseError{"empty and/or"};
      // De Morgan: under negation, and<->or.
      bool conj = (op == "and") ^ negate;
      if (conj) { // conjunction: cross product of children
        Formula acc{Clause{}}; // == true
        for (size_t i = 1; i < e.list.size(); ++i)
          acc = and_formula(acc, to_dnf(e.list[i], env, negate));
        return acc;
      } else {    // disjunction: union of children's clauses
        Formula acc; // == false
        for (size_t i = 1; i < e.list.size(); ++i) {
          Formula f = to_dnf(e.list[i], env, negate);
          acc.insert(acc.end(), f.begin(), f.end());
          if (acc.size() > MAX_CLAUSES) throw Unsupported{"DNF too large"};
        }
        return acc;
      }
    }
    if (op == "=>") {
      // (=> a1 a2 ... an) == (or (not a1) ... (not a_{n-1}) an)
      if (e.list.size() < 3) throw ParseError{"bad =>"};
      size_t n = e.list.size();
      if (!negate) { // OR of the negated premises and the (positive) conclusion
        Formula acc;
        for (size_t i = 1; i + 1 < n; ++i) {
          Formula f = to_dnf(e.list[i], env, true);
          acc.insert(acc.end(), f.begin(), f.end());
        }
        Formula last = to_dnf(e.list[n - 1], env, false);
        acc.insert(acc.end(), last.begin(), last.end());
        if (acc.size() > MAX_CLAUSES) throw Unsupported{"DNF too large"};
        return acc;
      } else {       // not(=>) == a1 and ... and a_{n-1} and (not an)
        Formula acc{Clause{}};
        for (size_t i = 1; i + 1 < n; ++i)
          acc = and_formula(acc, to_dnf(e.list[i], env, false));
        acc = and_formula(acc, to_dnf(e.list[n - 1], env, true));
        return acc;
      }
    }
    if (op == "xor") {
      // support 2-ary xor only (n-ary parity blows up without formula negation).
      if (e.list.size() != 3) throw Unsupported{"n-ary xor"};
      // xor(a,b) == (a and not b) or (not a and b)
      // not xor(a,b) == (a and b) or (not a and not b)
      bool nb = !negate; // sign of b in the first conjunct
      Formula t1 = and_formula(to_dnf(e.list[1], env, false),
                               to_dnf(e.list[2], env, nb));
      Formula t2 = and_formula(to_dnf(e.list[1], env, true),
                               to_dnf(e.list[2], env, !nb));
      t1.insert(t1.end(), t2.begin(), t2.end());
      if (t1.size() > MAX_CLAUSES) throw Unsupported{"DNF too large"};
      return t1;
    }
    if (op == "ite") {
      // boolean ite(c,t,e) == (c and t) or (not c and e)
      // not ite(c,t,e)     == (c and not t) or (not c and not e)
      if (e.list.size() != 4) throw ParseError{"bad ite"};
      Formula br1 = and_formula(to_dnf(e.list[1], env, false),
                                to_dnf(e.list[2], env, negate));
      Formula br2 = and_formula(to_dnf(e.list[1], env, true),
                                to_dnf(e.list[3], env, negate));
      br1.insert(br1.end(), br2.begin(), br2.end());
      if (br1.size() > MAX_CLAUSES) throw Unsupported{"DNF too large"};
      return br1;
    }

    // otherwise: a relational leaf.  Capture it (with its negation sign and the
    // active let-environment) as a single-literal clause.
    return Formula{Clause{Literal{&e, negate, env}}};
  }

  // map a predicate name to its AstKind (integer relational or FP relational).
  // returns Bool for "not a predicate".
  uint16_t predicate_kind(const std::string &op, bool operands_fp) {
    if (op == "=") return operands_fp ? Equal : Equal; // bitwise equality either way
    if (op == "distinct") return Distinct;
    if (op == "bvult") return Ult;
    if (op == "bvule") return Ule;
    if (op == "bvugt") return Ugt;
    if (op == "bvuge") return Uge;
    if (op == "bvslt") return Slt;
    if (op == "bvsle") return Sle;
    if (op == "bvsgt") return Sgt;
    if (op == "bvsge") return Sge;
    if (op == "fp.eq") return FOeq;
    if (op == "fp.lt") return FOlt;
    if (op == "fp.leq") return FOle;
    if (op == "fp.gt") return FOgt;
    if (op == "fp.geq") return FOge;
    return Bool;
  }

  void emit_comparison(const SExpr &e0, const Env &env, bool negate) {
    const SExpr *ep = resolve(&e0, env);
    const SExpr &e = *ep;
    if (e.is_atom || e.list.empty() || !e.list[0].is_atom)
      throw Unsupported{"non-comparison in boolean position"};
    const std::string &op = e.list[0].atom;
    if (op == "not") { // double negation
      if (e.list.size() != 2) throw ParseError{"bad not"};
      emit_comparison(e.list[1], env, !negate);
      return;
    }
    if (op == "let") {
      if (e.list.size() != 3) throw ParseError{"bad let"};
      Env e2 = bind_let(e.list[1], env);
      // re-dispatch the body as a comparison (still under the same negate flag)
      if (negate) {
        // wrap: translate body as comparison, negated
        emit_comparison(e.list[2], e2, true);
      } else {
        emit_comparison(e.list[2], e2, false);
      }
      return;
    }

    // determine whether the operands are FP (affects '=' meaning only cosmetically)
    bool operands_fp = false;
    if (e.list.size() >= 2) operands_fp = looks_fp(e.list[1], env);

    uint16_t kind = predicate_kind(op, operands_fp);
    if (kind == Bool) throw Unsupported{"predicate '" + op + "'"};

    // n-ary '=' / 'distinct' expand to pairwise 2-operand comparisons.
    size_t nargs = e.list.size() - 1;
    if (nargs < 2) throw Unsupported{"comparison with <2 operands"};

    if (op == "=" || op == "distinct") {
      // (= a b c ...) => a=b, b=c, ... ; (distinct a b c ...) => all pairs.
      // Under negation, De Morgan turns a conjunction into a disjunction, which
      // jigsaw cannot represent -- reject unless it is a simple 2-operand form.
      if (nargs > 2 && negate)
        throw Unsupported{"negated n-ary =/distinct"};
      uint16_t base = (op == "=") ? Equal : Distinct;
      if (negate) base = negate_cmp(base);
      // Structural FP equality (SMT-LIB '=') differs from IEEE fp.eq: all NaNs
      // are one value and +0 != -0.  Bitwise Equal soundly UNDER-approximates
      // structural '=' (identical bits ==> same value or same-bits NaN ==>
      // structurally equal).  But bitwise Distinct does NOT imply structural
      // disequality: two NaNs with different bit patterns (e.g. sqrt(neg) -> -nan
      // 0xFFF8.. vs the canonical NaN 0x7FF8..) are bit-distinct yet structurally
      // equal, which would yield an unsound 'sat'.  We cannot express the
      // required "... and not both NaN" guard in the jigsaw AST, so reject
      // structural FP disequality (-> unknown) rather than risk a wrong answer.
      if (operands_fp && base == Distinct)
        throw Unsupported{"structural FP disequality (NaN-unsound in jigsaw)"};
      if (op == "=") {
        for (size_t i = 1; i + 1 < e.list.size(); ++i)
          make_constraint(base, e.list[i], e.list[i + 1], env);
      } else { // distinct: all unordered pairs
        for (size_t i = 1; i < e.list.size(); ++i)
          for (size_t j = i + 1; j < e.list.size(); ++j)
            make_constraint(base, e.list[i], e.list[j], env);
      }
      return;
    }

    if (nargs != 2) throw Unsupported{"n-ary comparison"};
    uint16_t k = negate ? negate_cmp(kind) : kind;
    if (k == Bool) throw Unsupported{"cannot negate predicate '" + op + "'"};
    make_constraint(k, e.list[1], e.list[2], env);
  }

  // cheap check whether a term is FP-sorted (used only to disambiguate '=').
  bool looks_fp(const SExpr &e0, const Env &env) {
    const SExpr *ep = resolve(&e0, env);
    const SExpr &e = *ep;
    if (e.is_atom) {
      auto it = vars.find(e.atom);
      if (it != vars.end()) return it->second.is_fp;
      return false;
    }
    if (e.list.empty() || !e.list[0].is_atom) return false;
    const std::string &op = e.list[0].atom;
    return op == "fp" || op.rfind("fp.", 0) == 0 ||
           op == "_"; // (_ +zero ..) etc handled elsewhere
  }

  // ---- constraint construction ------------------------------------------

  void make_constraint(uint16_t pred_kind, const SExpr &lhs, const SExpr &rhs,
                       const Env &env) {
    uint32_t budget = 4 + count_nodes(lhs, env) + count_nodes(rhs, env);
    auto c = std::make_shared<Constraint>(budget);
    AstNode *root = c->ast.get();
    root->set_kind(pred_kind);
    root->set_bits(1);

    AstNode *left = root->add_children();
    if (!left) throw Unsupported{"AST too large"};
    TermInfo li = build_term(lhs, env, c, left);

    AstNode *right = root->add_children();
    if (!right) throw Unsupported{"AST too large"};
    TermInfo ri = build_term(rhs, env, c, right);
    (void)li; (void)ri;

    c->ops[pred_kind] = true;
    // jigsaw recomputes the comparison operands from the JIT'd function, so the
    // Constraint's op1/op2 are unused on this path; leave them 0.
    c->op1 = 0;
    c->op2 = 0;

    uint32_t khash = isRelationalKind(pred_kind) ? (uint32_t)Bool : (uint32_t)pred_kind;
    root->set_hash(xxhash(left->hash(), (khash << 16) | 1, right->hash()));

    task->add_constraint(c, pred_kind);
    DBG("constraint kind=%u budget=%u nodes\n", pred_kind, budget);
  }

  // upper bound on the number of AstNodes a term expands to (lets are followed so
  // multiply-referenced bindings are counted per use, matching build_term).
  uint32_t count_nodes(const SExpr &e0, const Env &env) {
    const SExpr *ep = resolve(&e0, env);
    const SExpr &e = *ep;
    if (e.is_atom) {
      if (vars.count(e.atom)) return 2; // Read (+ optional Extract)
      return 1;                          // constant / rounding-mode / other
    }
    if (!e.list.empty() && e.list[0].is_atom && e.list[0].atom == "let") {
      Env e2 = bind_let(e.list[1], env);
      return count_nodes(e.list[2], e2);
    }
    uint32_t s = 2; // this node (+ slack for Extract wrappers)
    for (const auto &c : e.list) s += count_nodes(c, env);
    return s;
  }

  // Fill a Read node (and register its bytes) exactly like rgd-parser's map_arg:
  // each input byte gets its own local slot; the first byte's slot indexes the
  // node hash and shape.  The JIT reads `bits/8` consecutive slots.
  void fill_read(AstNode *node, const std::shared_ptr<Constraint> &c,
                 uint32_t offset, uint32_t bits) {
    uint32_t length = bits / 8;
    uint32_t first_arg = 0;
    uint32_t off = offset;
    for (uint32_t k = 0; k < length; ++k, ++off) {
      uint32_t ai;
      auto it = c->local_map.find(off);
      if (it == c->local_map.end()) {
        ai = (uint32_t)c->input_args.size();
        c->inputs.insert({off, 0});           // all-zero seed
        c->local_map[off] = ai;
        c->input_args.push_back(std::make_pair(true, 0)); // gidx filled by finalize
      } else {
        ai = it->second;
      }
      if (k == 0) {
        c->shapes[off] = length;
        first_arg = ai;
      } else {
        c->shapes[off] = 0;
      }
    }
    node->set_kind(Read);
    node->set_bits(bits);
    node->set_index(offset);
    node->set_hash(xxhash(length * 8, Read, first_arg));
  }

  void fill_const(AstNode *node, const std::shared_ptr<Constraint> &c,
                  uint64_t value, uint32_t bits) {
    if (bits > 64) throw Unsupported{"constant wider than 64 bits"};
    uint32_t ai = (uint32_t)c->input_args.size();
    node->set_kind(Constant);
    node->set_bits(bits);
    node->set_index(ai);
    c->input_args.push_back(std::make_pair(false, value));
    c->const_num += 1;
    node->set_hash(xxhash(bits, Constant, ai));
  }

  // Build a variable reference: a byte-aligned Read, optionally wrapped in an
  // Extract to trim to a non-byte-multiple declared width.
  TermInfo build_var(const VarInfo &vi, const std::shared_ptr<Constraint> &c,
                     AstNode *ret) {
    if (vi.bits % 8 == 0) {
      fill_read(ret, c, vi.offset, vi.bits);
    } else {
      uint32_t abits = ((vi.bits + 7) / 8) * 8;
      ret->set_kind(Extract);
      ret->set_bits(vi.bits);
      ret->set_index(0); // low bit
      AstNode *rd = ret->add_children();
      if (!rd) throw Unsupported{"AST too large"};
      fill_read(rd, c, vi.offset, abits);
      ret->set_hash(xxhash(vi.bits, Extract, rd->hash()));
    }
    return {(uint16_t)vi.bits, vi.is_fp};
  }

  // Build an arbitrary BV/FP term into `ret`.
  TermInfo build_term(const SExpr &e0, const Env &env,
                      const std::shared_ptr<Constraint> &c, AstNode *ret) {
    const SExpr *ep = resolve(&e0, env);
    const SExpr &e = *ep;

    if (e.is_atom) {
      auto vit = vars.find(e.atom);
      if (vit != vars.end()) return build_var(vit->second, c, ret);
      uint64_t v;
      uint32_t w;
      if (parse_bits_literal(e.atom, v, w)) {
        fill_const(ret, c, v, w);
        return {(uint16_t)w, false};
      }
      throw Unsupported{"atom '" + e.atom + "'"};
    }

    if (e.list.empty()) throw ParseError{"empty application"};
    const SExpr &h = e.list[0];

    if (!h.is_atom) {
      // indexed operator application: ((_ ...) args...)
      return build_indexed_app(e, env, c, ret);
    }

    const std::string &op = h.atom;

    if (op == "let") {
      if (e.list.size() != 3) throw ParseError{"bad let"};
      Env e2 = bind_let(e.list[1], env);
      return build_term(e.list[2], e2, c, ret);
    }
    if (op == "_") {
      return build_indexed_atom(e, c, ret);
    }
    if (op == "fp") {
      return build_fp_literal(e, c, ret);
    }

    // concat needs special ordering: RGD's Concat(child0, child1) stores child0
    // in the LOW bits (c1 | (c2 << c1.bits)), whereas SMT-LIB (concat a b) puts
    // `a` in the HIGH bits.  Build it separately so the bit order is correct.
    if (op == "concat") {
      std::vector<const SExpr *> operands;
      for (size_t i = 1; i < e.list.size(); ++i) operands.push_back(&e.list[i]);
      if (operands.size() < 2) throw ParseError{"bad concat"};
      return build_concat(operands, 0, operands.size() - 1, env, c, ret);
    }

    // ---- BV binary / n-ary (left-associative) ----
    struct BinMap { const char *name; uint16_t kind; };
    static const BinMap bvbin[] = {
      {"bvadd", Add}, {"bvsub", Sub}, {"bvmul", Mul}, {"bvudiv", UDiv},
      {"bvsdiv", SDiv}, {"bvurem", URem}, {"bvsrem", SRem}, {"bvand", And},
      {"bvor", Or}, {"bvxor", Xor}, {"bvshl", Shl}, {"bvlshr", LShr},
      {"bvashr", AShr},
    };
    for (const auto &m : bvbin) {
      if (op == m.name) {
        std::vector<const SExpr *> operands;
        for (size_t i = 1; i < e.list.size(); ++i) operands.push_back(&e.list[i]);
        if (operands.size() < 2) throw ParseError{std::string("bad ") + m.name};
        return build_fold(m.kind, operands, operands.size() - 1, env, c, ret);
      }
    }

    // ---- BV unary ----
    if (op == "bvneg" || op == "bvnot") {
      if (e.list.size() != 2) throw ParseError{"bad " + op};
      ret->set_kind(op == "bvneg" ? Neg : Not);
      AstNode *ch = ret->add_children();
      if (!ch) throw Unsupported{"AST too large"};
      TermInfo ci = build_term(e.list[1], env, c, ch);
      ret->set_bits(ci.bits);
      c->ops[ret->kind()] = true;
      // unary hash mirrors rgd-parser's unary path
      ret->set_hash(xxhash(ci.bits, ret->kind(), ch->hash()));
      return {ci.bits, false};
    }

    // ---- FP arithmetic ----
    return build_fp_op(e, env, c, ret);
  }

  // build a left-associative fold of `kind` over operands[0..hi].
  TermInfo build_fold(uint16_t kind, const std::vector<const SExpr *> &operands,
                      size_t hi, const Env &env,
                      const std::shared_ptr<Constraint> &c, AstNode *ret) {
    ret->set_kind(kind);
    AstNode *left = ret->add_children();
    if (!left) throw Unsupported{"AST too large"};
    TermInfo li;
    if (hi == 1) {
      li = build_term(*operands[0], env, c, left);
    } else {
      li = build_fold(kind, operands, hi - 1, env, c, left);
    }
    AstNode *right = ret->add_children();
    if (!right) throw Unsupported{"AST too large"};
    TermInfo ri = build_term(*operands[hi], env, c, right);

    uint16_t bits;
    if (kind == Concat) bits = (uint16_t)(li.bits + ri.bits);
    else bits = li.bits; // arithmetic / bitwise / shift: result width = lhs width
    ret->set_bits(bits);
    c->ops[kind] = true;
    uint32_t khash = isRelationalKind(kind) ? (uint32_t)Bool : (uint32_t)kind;
    ret->set_hash(xxhash(left->hash(), (khash << 16) | bits, right->hash()));
    return {bits, false};
  }

  // Build an SMT-LIB (concat operands[lo..hi]) with operands[lo] most
  // significant.  RGD's Concat(child0, child1) treats child0 as the LOW part, so
  // we recurse with the remaining (lower) operands as child0 and the current
  // (highest) operand as child1.
  TermInfo build_concat(const std::vector<const SExpr *> &operands, size_t lo,
                        size_t hi, const Env &env,
                        const std::shared_ptr<Constraint> &c, AstNode *ret) {
    if (lo == hi) return build_term(*operands[lo], env, c, ret);
    ret->set_kind(Concat);
    // child0 = low part = concat(operands[lo+1..hi])
    AstNode *low = ret->add_children();
    if (!low) throw Unsupported{"AST too large"};
    TermInfo li = build_concat(operands, lo + 1, hi, env, c, low);
    // child1 = high part = operands[lo]
    AstNode *high = ret->add_children();
    if (!high) throw Unsupported{"AST too large"};
    TermInfo hi_ti = build_term(*operands[lo], env, c, high);
    uint16_t bits = (uint16_t)(li.bits + hi_ti.bits);
    ret->set_bits(bits);
    c->ops[Concat] = true;
    ret->set_hash(xxhash(low->hash(), ((uint32_t)Concat << 16) | bits, high->hash()));
    return {bits, false};
  }

  // ((_ extract i j) x), ((_ zero_extend k) x), ((_ sign_extend k) x),
  // ((_ to_fp eb sb) rm x)
  TermInfo build_indexed_app(const SExpr &e, const Env &env,
                             const std::shared_ptr<Constraint> &c, AstNode *ret) {
    const SExpr &idx = e.list[0]; // (_ name args...)
    if (idx.list.size() < 2 || !idx.list[1].is_atom)
      throw ParseError{"bad indexed op"};
    const std::string &name = idx.list[1].atom;

    if (name == "extract") {
      uint64_t hi, lo;
      if (!parse_uint(idx.list[2].atom, hi) || !parse_uint(idx.list[3].atom, lo))
        throw ParseError{"bad extract"};
      ret->set_kind(Extract);
      ret->set_bits((uint16_t)(hi - lo + 1));
      ret->set_index((uint32_t)lo);
      AstNode *ch = ret->add_children();
      if (!ch) throw Unsupported{"AST too large"};
      build_term(e.list[1], env, c, ch);
      c->ops[Extract] = true;
      ret->set_hash(xxhash(ret->bits(), Extract, ch->hash()));
      return {ret->bits(), false};
    }
    if (name == "zero_extend" || name == "sign_extend") {
      uint64_t k;
      if (!parse_uint(idx.list[2].atom, k)) throw ParseError{"bad extend"};
      uint16_t kind = (name == "zero_extend") ? ZExt : SExt;
      ret->set_kind(kind);
      AstNode *ch = ret->add_children();
      if (!ch) throw Unsupported{"AST too large"};
      TermInfo ci = build_term(e.list[1], env, c, ch);
      ret->set_bits((uint16_t)(ci.bits + k));
      c->ops[kind] = true;
      ret->set_hash(xxhash(ret->bits(), kind, ch->hash()));
      return {ret->bits(), false};
    }
    if (name == "to_fp") {
      return build_to_fp(e, env, c, ret, /*unsigned_src=*/false);
    }
    if (name == "to_fp_unsigned") {
      return build_to_fp(e, env, c, ret, /*unsigned_src=*/true);
    }
    throw Unsupported{"indexed op '" + name + "'"};
  }

  // (_ bvN W) as a term, or FP special constants (_ +zero eb sb) etc.
  TermInfo build_indexed_atom(const SExpr &e,
                              const std::shared_ptr<Constraint> &c, AstNode *ret) {
    if (e.list.size() < 2 || !e.list[1].is_atom) throw ParseError{"bad (_ ..)"};
    const std::string &name = e.list[1].atom;
    if (name.rfind("bv", 0) == 0) {
      uint64_t v;
      if (!parse_uint(name.substr(2), v)) throw ParseError{"bad (_ bvN W)"};
      uint64_t w;
      if (!parse_uint(e.list[2].atom, w)) throw ParseError{"bad (_ bvN W) width"};
      fill_const(ret, c, v, (uint32_t)w);
      return {(uint16_t)w, false};
    }
    // FP specials: (_ +zero eb sb) / -zero / +oo / -oo / NaN
    uint64_t eb, sb;
    if (e.list.size() >= 4 && parse_uint(e.list[2].atom, eb) &&
        parse_uint(e.list[3].atom, sb)) {
      uint32_t width = (uint32_t)(eb + sb);
      if (width != 32 && width != 64) throw Unsupported{"FP special width"};
      uint32_t ew = (uint32_t)eb;
      uint32_t sw = (uint32_t)(sb - 1); // stored significand bits
      uint64_t expmask = (ew >= 64) ? ~0ull : ((1ull << ew) - 1);
      uint64_t sigmask = (sw >= 64) ? ~0ull : ((1ull << sw) - 1);
      uint64_t bits = 0;
      if (name == "+zero") bits = 0;
      else if (name == "-zero") bits = 1ull << (ew + sw);
      else if (name == "+oo") bits = expmask << sw;
      else if (name == "-oo") bits = (1ull << (ew + sw)) | (expmask << sw);
      else if (name == "NaN") bits = (expmask << sw) | (1ull << (sw - 1)); // qNaN
      else throw Unsupported{"(_ " + name + " ..)"};
      (void)sigmask;
      fill_const(ret, c, bits, width);
      return {(uint16_t)width, true};
    }
    throw Unsupported{"(_ " + name + " ..)"};
  }

  // (fp #b<sign> <exp> <sig>) literal
  TermInfo build_fp_literal(const SExpr &e,
                            const std::shared_ptr<Constraint> &c, AstNode *ret) {
    if (e.list.size() != 4) throw ParseError{"bad fp literal"};
    uint64_t sgn, exp, sig;
    uint32_t sw, ew, gw;
    if (!parse_bits_literal(e.list[1].atom, sgn, sw) ||
        !parse_bits_literal(e.list[2].atom, exp, ew) ||
        !parse_bits_literal(e.list[3].atom, sig, gw))
      throw ParseError{"bad fp literal fields"};
    uint32_t width = sw + ew + gw;
    if (width != 32 && width != 64) throw Unsupported{"fp literal width"};
    uint64_t bits = (sgn << (ew + gw)) | (exp << gw) | sig;
    fill_const(ret, c, bits, width);
    return {(uint16_t)width, true};
  }

  // to_fp in its several SMT-LIB overloads:
  //   ((_ to_fp eb sb) <bv>)                -- bit-pattern REINTERPRET (no rm)
  //   ((_ to_fp eb sb) rm <fp>)             -- FP -> FP convert (FpExt / FpTrunc)
  //   ((_ to_fp eb sb) rm <bv>)             -- signed machine int -> FP (SiToFp)
  //   ((_ to_fp_unsigned eb sb) rm <bv>)    -- unsigned machine int -> FP (UiToFp)
  //   ((_ to_fp eb sb) rm <decimal/real>)   -- real literal -> FP constant
  TermInfo build_to_fp(const SExpr &e, const Env &env,
                       const std::shared_ptr<Constraint> &c, AstNode *ret,
                       bool unsigned_src) {
    const SExpr &idx = e.list[0];
    uint64_t eb, sb;
    if (idx.list.size() < 4 || !parse_uint(idx.list[2].atom, eb) ||
        !parse_uint(idx.list[3].atom, sb))
      throw ParseError{"bad to_fp"};
    uint32_t width = (uint32_t)(eb + sb);
    if (width != 32 && width != 64) throw Unsupported{"to_fp width"};

    // Form 1: ((_ to_fp eb sb) <bv>) with NO rounding mode -- a bit-pattern
    // reinterpretation of a width-matching bitvector.  In our bit-pattern FP
    // model an FP value IS its iN encoding, so this is a no-op: build the source
    // in place and re-tag it as FP.
    if (!unsigned_src && e.list.size() == 2) {
      TermInfo ci = build_term(e.list[1], env, c, ret);
      if (ci.bits != width)
        throw Unsupported{"to_fp bit-reinterpret width mismatch"};
      return {(uint16_t)width, true};
    }

    // Remaining forms carry a rounding mode: e.list[1] = rm, e.list[2] = source.
    if (e.list.size() != 3) throw Unsupported{"to_fp form"};
    const SExpr &src = e.list[2];

    // Decimal / real literal source -> constant (rounding mode ignored: the
    // literal already names the exact value; nearest is fine for our purposes).
    double d;
    if (!unsigned_src && eval_real(src, d)) {
      fill_const(ret, c, fp_to_bits(d, width), width);
      return {(uint16_t)width, true};
    }

    // Determine whether the (symbolic) source is FP or a bitvector.  looks_fp
    // treats every (_ ..) as FP, but (_ bvN W) is a bitvector constant, so
    // override that case.
    bool src_fp = !unsigned_src && looks_fp(src, env);
    const SExpr *sr = resolve(&src, env);
    if (!sr->is_atom && !sr->list.empty() && sr->list[0].is_atom &&
        sr->list[0].atom == "_" && sr->list.size() >= 2 && sr->list[1].is_atom &&
        sr->list[1].atom.rfind("bv", 0) == 0)
      src_fp = false; // (_ bvN W) is a bitvector constant, not FP

    AstNode *ch = ret->add_children();
    if (!ch) throw Unsupported{"AST too large"};
    TermInfo ci = build_term(src, env, c, ch);

    uint16_t kind;
    if (src_fp) {
      // FP -> FP: widen with FpExt, narrow with FpTrunc.  Equal width would be a
      // redundant no-op cast; jigsaw's FpExt/FpTrunc require differing widths.
      if (width > ci.bits) kind = FpExt;
      else if (width < ci.bits) kind = FpTrunc;
      else throw Unsupported{"redundant to_fp (FP->FP same width)"};
    } else {
      // machine integer -> FP.
      kind = unsigned_src ? UiToFp : SiToFp;
    }
    ret->set_kind(kind);
    ret->set_bits((uint16_t)width);
    c->ops[kind] = true;
    ret->set_hash(xxhash((uint16_t)width, kind, ch->hash()));
    return {(uint16_t)width, true};
  }

  bool eval_real(const SExpr &e, double &out) {
    if (e.is_atom) {
      char *end = nullptr;
      double d = std::strtod(e.atom.c_str(), &end);
      if (end && *end == '\0' && end != e.atom.c_str()) { out = d; return true; }
      return false;
    }
    if (!e.list.empty() && e.list[0].is_atom) {
      const std::string &op = e.list[0].atom;
      if (op == "-" && e.list.size() == 2) {
        double d;
        if (eval_real(e.list[1], d)) { out = -d; return true; }
      }
      if (op == "/" && e.list.size() == 3) {
        double a, b;
        if (eval_real(e.list[1], a) && eval_real(e.list[2], b) && b != 0) {
          out = a / b;
          return true;
        }
      }
    }
    return false;
  }

  // FP arithmetic ops (some take a leading rounding-mode argument, which we skip
  // because the JIT uses the native/default rounding mode).
  TermInfo build_fp_op(const SExpr &e, const Env &env,
                       const std::shared_ptr<Constraint> &c, AstNode *ret) {
    const std::string &op = e.list[0].atom;

    auto build_unary = [&](uint16_t kind, size_t argidx) -> TermInfo {
      ret->set_kind(kind);
      AstNode *ch = ret->add_children();
      if (!ch) throw Unsupported{"AST too large"};
      TermInfo ci = build_term(e.list[argidx], env, c, ch);
      ret->set_bits(ci.bits);
      c->ops[kind] = true;
      ret->set_hash(xxhash(ci.bits, kind, ch->hash()));
      return {ci.bits, true};
    };
    auto build_binary = [&](uint16_t kind, size_t a, size_t b) -> TermInfo {
      ret->set_kind(kind);
      AstNode *l = ret->add_children();
      if (!l) throw Unsupported{"AST too large"};
      TermInfo li = build_term(e.list[a], env, c, l);
      AstNode *r = ret->add_children();
      if (!r) throw Unsupported{"AST too large"};
      TermInfo ri = build_term(e.list[b], env, c, r);
      (void)ri;
      ret->set_bits(li.bits);
      c->ops[kind] = true;
      ret->set_hash(xxhash(l->hash(), ((uint32_t)kind << 16) | li.bits, r->hash()));
      return {li.bits, true};
    };

    // rounding-mode-carrying binary ops: (fp.add rm a b)
    if (op == "fp.add") return build_binary(FAdd, 2, 3);
    if (op == "fp.sub") return build_binary(FSub, 2, 3);
    if (op == "fp.mul") return build_binary(FMul, 2, 3);
    if (op == "fp.div") return build_binary(FDiv, 2, 3);
    // no rounding mode
    if (op == "fp.rem") return build_binary(FRem, 1, 2);
    if (op == "fp.min") return build_binary(FpMin, 1, 2);
    if (op == "fp.max") return build_binary(FpMax, 1, 2);
    // rounding-mode-carrying unary: (fp.sqrt rm x)
    if (op == "fp.sqrt") return build_unary(FpSqrt, 2);
    // no rounding mode
    if (op == "fp.neg") return build_unary(FNeg, 1);
    if (op == "fp.abs") return build_unary(FpFabs, 1);

    if (op == "fp.roundToIntegral") {
      // (fp.roundToIntegral rm x) -- map rm to the fp_rounding_mode selector.
      if (e.list.size() != 3) throw ParseError{"bad roundToIntegral"};
      uint32_t sel;
      const std::string &rm = e.list[1].atom;
      if (rm == "roundNearestTiesToAway" || rm == "RNA") sel = 0;
      else if (rm == "roundNearestTiesToEven" || rm == "RNE") sel = 1;
      else if (rm == "roundTowardPositive" || rm == "RTP") sel = 2;
      else if (rm == "roundTowardNegative" || rm == "RTN") sel = 3;
      else if (rm == "roundTowardZero" || rm == "RTZ") sel = 4;
      else throw Unsupported{"rounding mode " + rm};
      ret->set_kind(FpRound);
      AstNode *ch = ret->add_children();
      if (!ch) throw Unsupported{"AST too large"};
      TermInfo ci = build_term(e.list[2], env, c, ch);
      ret->set_bits(ci.bits);
      ret->set_index(sel);
      c->ops[FpRound] = true;
      ret->set_hash(xxhash(ci.bits, FpRound, ch->hash()));
      return {ci.bits, true};
    }

    throw Unsupported{"operator '" + op + "'"};
  }
};

// -------------------------------------------------------------------------
// model decoding / printing
// -------------------------------------------------------------------------

static void print_model(const Translator &tr, const uint8_t *buf, size_t size) {
  printf("(\n");
  for (const auto &name : tr.var_order) {
    const VarInfo &vi = tr.vars.at(name);
    uint32_t wbytes = (vi.bits + 7) / 8;
    // little-endian read of the (possibly wide) value
    std::vector<uint8_t> bytes(wbytes, 0);
    for (uint32_t k = 0; k < wbytes; ++k) {
      size_t off = vi.offset + k;
      bytes[k] = (off < size) ? buf[off] : 0;
    }
    if (vi.is_fp) {
      // (fp #b<sign> #b<exp> #b<sig>)
      uint32_t ew = (vi.bits == 32) ? 8 : 11;
      uint32_t sw = (vi.bits == 32) ? 23 : 52;
      uint64_t v = 0;
      for (uint32_t k = 0; k < wbytes; ++k) v |= (uint64_t)bytes[k] << (8 * k);
      auto bin = [](uint64_t val, uint32_t nbits) {
        std::string s;
        for (int i = (int)nbits - 1; i >= 0; --i) s.push_back(((val >> i) & 1) ? '1' : '0');
        return s;
      };
      uint64_t sign = (v >> (ew + sw)) & 1;
      uint64_t exp = (v >> sw) & ((ew >= 64) ? ~0ull : ((1ull << ew) - 1));
      uint64_t sig = v & ((sw >= 64) ? ~0ull : ((1ull << sw) - 1));
      printf("  (define-fun %s () %s (fp #b%s #b%s #b%s))\n", name.c_str(),
             vi.bits == 32 ? "Float32" : "Float64", bin(sign, 1).c_str(),
             bin(exp, ew).c_str(), bin(sig, sw).c_str());
    } else {
      // BV value as a width-exact #b binary literal (works for any width)
      std::string s;
      for (int i = (int)vi.bits - 1; i >= 0; --i) {
        uint8_t byte = bytes[i / 8];
        s.push_back(((byte >> (i % 8)) & 1) ? '1' : '0');
      }
      printf("  (define-fun %s () (_ BitVec %u) #b%s)\n", name.c_str(), vi.bits,
             s.c_str());
    }
  }
  printf(")\n");
}

} // namespace

int main(int argc, char **argv) {
  bool use_z3 = getenv("SMT_USE_Z3") != nullptr;
  bool use_jigsaw = getenv("SMT_NO_JIGSAW") == nullptr;
  bool report_time = getenv("SMT_TIME") != nullptr;
  const char *path = nullptr;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--z3") use_z3 = true;
    else if (a == "--no-jigsaw") use_jigsaw = false;
    else if (a == "--time") report_time = true;
    else if (a == "-h" || a == "--help") {
      fprintf(stderr, "Usage: %s [--z3] [--no-jigsaw] [--time] file.smt2\n", argv[0]);
      return 2;
    } else {
      path = argv[i];
    }
  }
  if (!path) {
    fprintf(stderr, "Usage: %s [--z3] [--no-jigsaw] [--time] file.smt2\n", argv[0]);
    return 2;
  }

  // read the whole file
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) {
    fprintf(stderr, "failed to open %s\n", path);
    return 2;
  }
  std::stringstream ss;
  ss << ifs.rdbuf();
  std::string content = ss.str();

  // Phase timers (microseconds).  parse = SMT-LIB read + DNF translation +
  // SearchTask construction; solve = wall time of the whole solver loop; the
  // codegen/jit/gd breakdown below is the jigsaw-internal split of solve time.
  using Clock = std::chrono::steady_clock;
  auto us_since = [](Clock::time_point t) {
    return std::chrono::duration<double, std::micro>(Clock::now() - t).count();
  };
  double parse_us = 0, solve_us = 0;
  JITSolver *jit_ptr = nullptr;
  auto emit_time = [&]() {
    if (!report_time) return;
    uint64_t codegen = 0, jit = 0, gd = 0;
    if (jit_ptr) {
      codegen = jit_ptr->get_codegen_time();
      jit = jit_ptr->get_jit_time();
      gd = jit_ptr->get_solving_time();
    }
    fprintf(stderr,
            "TIME parse=%.0f codegen=%lu jit=%lu gd=%lu solve=%.0f total=%.0f (us)\n",
            parse_us, codegen, jit, gd, solve_us, parse_us + solve_us);
  };

  auto t_start = Clock::now();
  Translator tr;
  bool has_constraints = false;
  try {
    SexpReader reader(content);
    // Read every command first and keep them alive for the whole run.  DNF
    // Literals capture bare `const SExpr *` pointers into these command trees
    // (the assertion sub-expressions) and are consumed later in build_tasks(),
    // so the parsed SExprs must outlive command processing.  All commands are
    // read (and any vector reallocation happens) before run_command takes a
    // single pointer, so the trees are stable once we start processing them.
    std::vector<SExpr> cmds;
    while (!reader.eof()) {
      SExpr cmd = reader.read();
      cmds.push_back(std::move(cmd));
    }
    for (const auto &cmd : cmds)
      tr.run_command(cmd);
    has_constraints = tr.build_tasks();
    parse_us = us_since(t_start);
  } catch (const Unsupported &u) {
    fprintf(stderr, "unsupported: %s\n", u.msg.c_str());
    printf("unknown\n");
    return 0;
  } catch (const ParseError &p) {
    fprintf(stderr, "parse error: %s\n", p.msg.c_str());
    printf("unknown\n");
    return 0;
  } catch (const std::exception &ex) {
    fprintf(stderr, "error: %s\n", ex.what());
    printf("unknown\n");
    return 0;
  }

  // virtual input buffer (all-zero seed)
  size_t in_size = tr.total_bytes ? tr.total_bytes : 1;
  std::vector<uint8_t> in_buf(in_size, 0);
  std::vector<uint8_t> out_buf(in_size, 0);

  if (tr.trivial_sat) {
    // some DNF clause is unconditionally true -> the formula is satisfiable
    printf("sat\n");
    print_model(tr, in_buf.data(), in_buf.size());
    emit_time();
    return 0;
  }
  if (!has_constraints) {
    // no clauses at all -> the formula reduced to false; jigsaw cannot prove
    // unsat, so report unknown (z3, if asked, handles per-clause unsat below).
    printf("unknown\n");
    emit_time();
    return 0;
  }

  // build the solver chain (jigsaw first for speed; optional z3 as a complete,
  // FP-aware fallback).  i2s is intentionally excluded: it solves one constraint
  // at a time and would falsely report SAT on a multi-constraint conjunction.
  std::vector<std::shared_ptr<Solver>> solvers;
  if (use_jigsaw) {
    auto jit = std::make_shared<JITSolver>();
    jit_ptr = jit.get(); // for the codegen/jit/gd timing breakdown
    solvers.emplace_back(std::move(jit));
  }
  if (use_z3) solvers.emplace_back(std::make_shared<Z3Solver>());
  if (solvers.empty()) {
    fprintf(stderr, "no solver selected\n");
    printf("unknown\n");
    emit_time();
    return 0;
  }

  // The formula (a DNF) is SAT iff ANY clause-task is SAT; it is UNSAT iff EVERY
  // clause-task is proven UNSAT (only z3 can do that).  Solve each task with the
  // chain; the first SAT wins.  Track whether all tasks were shown unsat.
  auto t_solve = Clock::now();
  bool all_unsat = true;
  for (auto &clause_task : tr.tasks) {
    bool this_unsat = false;
    for (auto &solver : solvers) {
      size_t out_size = 0;
      solver_result_t r;
      try {
        r = solver->solve(clause_task, in_buf.data(), in_buf.size(),
                          out_buf.data(), out_size);
      } catch (const std::exception &ex) {
        fprintf(stderr, "solver error: %s\n", ex.what());
        continue;
      }
      if (r == SOLVER_SAT) {
        solve_us = us_since(t_solve);
        printf("sat\n");
        print_model(tr, out_buf.data(), out_size ? out_size : out_buf.size());
        emit_time();
        return 0;
      } else if (r == SOLVER_UNSAT) {
        this_unsat = true; // this clause is unsat; try the next clause
        break;
      }
      // SOLVER_TIMEOUT / SOLVER_ERROR: try the next solver for this clause
    }
    if (!this_unsat) all_unsat = false; // clause neither SAT nor proven UNSAT
  }
  solve_us = us_since(t_solve);
  if (all_unsat) {
    // every clause proven unsat -> the whole DNF (formula) is unsat
    printf("unsat\n");
    emit_time();
    return 0;
  }
  printf("unknown\n");
  emit_time();
  return 0;
}
