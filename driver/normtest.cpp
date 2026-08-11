// normtest -- a truth-table oracle for the RGD parser's normalizer.
//
// parsers/rgd-parser.cpp turns a traced condition into a DNF in four stages:
// find_roots() lifts the label graph into a boolean skeleton over relational
// leaves, to_nnf() pushes negation down to those leaves, to_dnf() splits the
// disjunctions into clauses, and construct_task() makes one SearchTask per
// clause.  Nothing checked that the formula coming out means the same thing as
// the one going in.  The lit tests pin a handful of source shapes and the
// corpus sweeps count failed/empty parses -- neither can see a rewrite that
// produces a well-formed but WRONG formula, which stays silent all the way to a
// solver answer that flips the wrong branch.
//
// All four stages are checked as one unit, because the DNF is the only thing
// observable from outside: the tasks ARE the clauses, and a task's literals are
// its leaves plus their comparison kinds.  So this is not an NNF test -- an NNF
// that is right and a to_dnf that drops a clause fail here exactly the same
// way, which is what you want from an oracle.
//
//     SOUNDNESS     the DNF must equal (result ? !F : F) on every assignment
//     COMPLETENESS  a formula in the supported fragment must not be refused
//
// Both halves, because the bugs come in both flavours: a malformed LNot and a
// missing Xor root were refusals, while an inverted set_boolvalue() silently
// produced the wrong formula (task #127).
//
// Why not differential-test against driver/smttest.cpp's Translator::to_dnf,
// which normalizes the same way over S-expressions?  Because it is a peer, not
// an oracle -- same author, same mental model, and it already had the xor
// expansion the parser was missing, so agreeing with it proves nothing about
// the case that was broken.  A truth table cannot agree-and-both-be-wrong.
// (smttest is still the right tool for the follow-on: it becomes the z3 oracle
// once leaves carry real bitvector content, where enumerating assignments over
// independent leaves stops working.)
//
// See gen_term() for the fragment, and for why each shape is faithful to what
// __taint_union() can actually produce.

#include "parse-rgd.h"

#include "ast.h"
#include "task.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

using namespace rgd;

namespace {

// ---------------------------------------------------------------------------
// leaves
// ---------------------------------------------------------------------------

// Every relational predicate the parser lifts from an icmp.  A leaf may be any
// of them, not just equality: to_nnf negates a leaf by rewriting its kind to
// the complement, so a fragment of nothing but Equal/Distinct would leave eight
// of the ten pairs untested.
//
// Both columns are written out by hand, and neither may be computed from the
// code under test.  The first version of this file read the negation back
// through AstNode::negate_cmp() -- the same function to_nnf calls -- so
// mutating one of its arms (Ult -> Ugt instead of Uge) produced a parser that
// emitted the wrong predicate and an oracle that expected the wrong predicate,
// and 3610 checks passed.  An oracle that shares a table with its subject
// cannot see a bug in the table.
struct Pred {
  uint16_t dfsan;  // __dfsan::bv*
  uint16_t kind;   // the rgd::AstKind find_roots gives it
  uint16_t neg;    // what a negated literal of this leaf must read as
};
const Pred kPreds[] = {
  {__dfsan::bveq,  rgd::Equal,    rgd::Distinct},
  {__dfsan::bvneq, rgd::Distinct, rgd::Equal},
  {__dfsan::bvult, rgd::Ult,      rgd::Uge},  // !(a <u b) == a >=u b
  {__dfsan::bvule, rgd::Ule,      rgd::Ugt},
  {__dfsan::bvugt, rgd::Ugt,      rgd::Ule},
  {__dfsan::bvuge, rgd::Uge,      rgd::Ult},
  {__dfsan::bvslt, rgd::Slt,      rgd::Sge},
  {__dfsan::bvsle, rgd::Sle,      rgd::Sgt},
  {__dfsan::bvsgt, rgd::Sgt,      rgd::Sle},
  {__dfsan::bvsge, rgd::Sge,      rgd::Slt},
};
const size_t kNumPreds = sizeof(kPreds) / sizeof(kPreds[0]);

struct Leaf {
  dfsan_label byte = 0;  // the input byte it reads
  const Pred *pred = nullptr;
  uint64_t konst = 0;
};

// ---------------------------------------------------------------------------
// the formula, as the harness knows it
// ---------------------------------------------------------------------------

// Children are held as indices into Formula::terms, which is topologically
// ordered (children before parents).  That ordering is not cosmetic: labels are
// handed out in the same pass, and scan_labels() walks the union table linearly
// from 0, so a child must have a lower label than its parent.
struct Term {
  enum Kind : uint8_t {
    LeafRef,  // one of the relational leaves
    Const,    // a boolean constant operand
    Not,      // __dfsan::Not
    And, Or, Xor,
    BoolCmp,  // `bool ==/!= 0/1`, which find_roots folds to identity or LNot
  } kind;
  uint8_t leaf = 0;       // LeafRef: which leaf
  uint8_t value = 0;      // Const: the boolean constant
  bool negates = false;   // BoolCmp: whether this shape means !child
  int a = -1;             // lhs (Const or subterm)
  int b = -1;             // rhs; the single operand of Not and BoolCmp
  dfsan_label label = 0;  // union-table label; 0 for Const, which has no entry
};

struct Formula {
  std::vector<Term> terms;
  int root = -1;
  uint32_t nleaves = 0;
  std::vector<Leaf> leaves;

  bool eval(int i, uint32_t mask) const {
    const Term &t = terms[i];
    switch (t.kind) {
      case Term::LeafRef: return (mask >> t.leaf) & 1;
      case Term::Const:   return t.value != 0;
      case Term::Not:     return !eval(t.b, mask);
      case Term::BoolCmp: return t.negates ? !eval(t.b, mask) : eval(t.b, mask);
      case Term::And:     return eval(t.a, mask) && eval(t.b, mask);
      case Term::Or:      return eval(t.a, mask) || eval(t.b, mask);
      case Term::Xor:     return eval(t.a, mask) ^ eval(t.b, mask);
    }
    return false;
  }
  bool eval(uint32_t mask) const { return eval(root, mask); }

  // S-expression, for the failure report.
  void print(FILE *f, int i) const {
    const Term &t = terms[i];
    switch (t.kind) {
      case Term::LeafRef: fprintf(f, "L%u", t.leaf); return;
      case Term::Const:   fprintf(f, "%s", t.value ? "true" : "false"); return;
      case Term::Not:     fprintf(f, "(not "); print(f, t.b); fprintf(f, ")"); return;
      case Term::BoolCmp:
        fprintf(f, "(%s ", t.negates ? "bcmp-not" : "bcmp");
        print(f, t.b);
        fprintf(f, ")");
        return;
      case Term::And: fprintf(f, "(and "); break;
      case Term::Or:  fprintf(f, "(or ");  break;
      case Term::Xor: fprintf(f, "(xor "); break;
    }
    print(f, t.a); fprintf(f, " "); print(f, t.b); fprintf(f, ")");
  }
  void print(FILE *f) const {
    print(f, root);
    fprintf(f, "\n  where");
    for (uint32_t i = 0; i < nleaves; i++) {
      fprintf(f, "  L%u = (byte%u %s %#" PRIx64 ")", i, i,
              AstKindName[leaves[i].pred->kind], leaves[i].konst);
    }
  }
};

// ---------------------------------------------------------------------------
// the union table, as the parser reads it
// ---------------------------------------------------------------------------

// RGDAstParser takes a raw (base, size) buffer and dfsan_label_info is a flat
// packed struct, so the whole thing can be built in memory -- no instrumented
// target, no runtime, no shm.
class Store {
public:
  Store() { table_.reserve(512); table_.emplace_back(); } // label 0 == the constant label
  dfsan_label push(const dfsan_label_info &e) {
    table_.push_back(e);
    return static_cast<dfsan_label>(table_.size() - 1);
  }
  void *base() { return table_.data(); }
  size_t bytes() const { return table_.size() * sizeof(dfsan_label_info); }
  size_t count() const { return table_.size(); }
private:
  std::vector<dfsan_label_info> table_;
};

// one tainted input byte: op 0, offset in op1, input id in op2
dfsan_label build_input_byte(Store &s, uint32_t offset) {
  dfsan_label_info e{};
  e.op = 0;
  e.size = 8;
  e.op1.i = offset;
  e.op2.i = 0;
  return s.push(e);
}

// `input_byte <pred> c`.  For a cmp node info->size is the OPERAND width, not
// the result width (TaintPass), hence 8 rather than 1.  The symbolic side is
// l1: __taint_union() normalizes an icmp to `symbolic <pred> constant`, so a
// zero label on the right is the constant side.
dfsan_label build_leaf_cmp(Store &s, const Leaf &leaf) {
  dfsan_label_info e{};
  e.l1 = leaf.byte;
  e.l2 = 0;
  e.op = static_cast<uint16_t>(__dfsan::ICmp | (leaf.pred->dfsan << 8));
  e.size = 8;
  e.op2.i = leaf.konst;
  return s.push(e);
}

// A boolean connective.  size is 1 -- find_roots rejects "bool node width"
// otherwise, which is also why an -O0 build (where clang zero-extends both
// comparisons and xors them as i32) never reaches these arms at all.
dfsan_label build_connective(Store &s, uint16_t op, dfsan_label l1, uint64_t op1,
                             dfsan_label l2) {
  dfsan_label_info e{};
  e.l1 = l1;
  e.l2 = l2;
  e.op = op;
  e.size = 1;
  e.op1.i = op1;
  return s.push(e);
}

// `bool <eq|ne> <0|1>`, in either operand order.
dfsan_label build_bool_cmp(Store &s, dfsan_label child, uint16_t pred,
                           uint64_t c, bool const_on_left) {
  dfsan_label_info e{};
  e.op = static_cast<uint16_t>(__dfsan::ICmp | (pred << 8));
  e.size = 1;  // operand width: these compare i1 against i1
  if (const_on_left) {
    e.l1 = 0;
    e.op1.i = c;
    e.l2 = child;
  } else {
    e.l1 = child;
    e.l2 = 0;
    e.op2.i = c;
  }
  return s.push(e);
}

// ---------------------------------------------------------------------------
// generator
// ---------------------------------------------------------------------------

struct GenConfig {
  uint32_t nleaves = 4;
  uint32_t depth = 3;
  // Off by default, and see gen_term() for why: the shape cannot occur on a
  // real trace.  It was added because the *node* it produces can, and with it
  // on the parser failed -- fixed since (#130), and the suite now runs three
  // --const-pct configurations to keep it fixed.
  uint32_t const_pct = 0;     // chance a binary connective takes a constant lhs
  uint32_t boolcmp_pct = 15;  // chance of a `bool ==/!= 0/1` layer
};

class Gen {
public:
  Gen(uint64_t seed, const GenConfig &cfg) : rng_(seed), cfg_(cfg) {}

  // Build a formula and, in the same pass, the union table for it.
  void build(Formula &f, Store &s) {
    f.nleaves = cfg_.nleaves;
    for (uint32_t i = 0; i < cfg_.nleaves; i++) {
      Leaf leaf;
      // one distinct input byte per leaf.  Disjoint on purpose: sharing bytes
      // would couple leaves, and then not every assignment of the 2^n truth
      // table is realizable -- the oracle would be checking a formula over
      // variables that cannot actually vary independently.
      leaf.byte = build_input_byte(s, i);
      leaf.pred = &kPreds[rng_() % kNumPreds];
      // 0x41..0x50 over an 8-bit operand.  Away from 0, UINT8_MAX, INT8_MIN and
      // INT8_MAX on purpose: __taint_union() folds a comparison against the
      // extreme value of its own width to the constant label, so a leaf there
      // would not exist at all on a real trace.  It also keeps both truth
      // values reachable for every predicate, which is what makes the 2^n
      // enumeration honest.
      leaf.konst = 0x41 + i;
      f.leaves.push_back(leaf);
    }
    f.root = gen_term(f, s, cfg_.depth);
  }

private:
  int emit(Formula &f, Term &t) {
    f.terms.push_back(t);
    return static_cast<int>(f.terms.size() - 1);
  }

  int gen_term(Formula &f, Store &s, uint32_t depth) {
    // leaf, either because we ran out of depth or by choice
    if (depth == 0 || pct(25)) {
      Term t;
      t.kind = Term::LeafRef;
      t.leaf = static_cast<uint8_t>(rng_() % f.nleaves);
      t.label = build_leaf_cmp(s, f.leaves[t.leaf]);
      return emit(f, t);
    }

    // `bool ==/!= 0/1`.  Not a fold: find_roots treats it as a connective,
    // rewriting the node to a copy of the child or to LNot depending on the
    // predicate and the constant (the four-way case in its icmp arm).  Both
    // operand orders are live -- the icmp normalization in __taint_union()
    // computes the swapped predicate for its saturation check but does not
    // write it back, so a source-level `const == sym` keeps its shape.
    if (pct(cfg_.boolcmp_pct)) {
      int child = gen_term(f, s, depth - 1);
      bool eq = rng_() & 1;
      uint64_t c = rng_() & 1;
      bool const_on_left = rng_() & 1;
      Term t;
      t.kind = Term::BoolCmp;
      t.b = child;
      // eq: `x == 1` is x, `x == 0` is !x.  ne: the other way round.
      t.negates = eq ? (c == 0) : (c == 1);
      t.label = build_bool_cmp(s, f.terms[child].label,
                               eq ? __dfsan::bveq : __dfsan::bvneq, c,
                               const_on_left);
      return emit(f, t);
    }

    if (rng_() % 4 == 0) {
      // The runtime never emits a standalone Not opcode: it rewrites `1 ^ x`
      // (size 1) into one, so the operand lands in l2 and l1 is the zero label
      // (the op1_is_all_one fold).  Match that -- with the operand in l1
      // instead, find_roots would descend the other side and the arm's
      // children_size() check would see something different.
      int child = gen_term(f, s, depth - 1);
      Term t;
      t.kind = Term::Not;
      t.b = child;
      t.label = build_connective(s, __dfsan::Not, 0, 1, f.terms[child].label);
      return emit(f, t);
    }

    Term t;
    uint16_t op;
    switch (rng_() % 3) {
      case 0:  t.kind = Term::And; op = __dfsan::And; break;
      case 1:  t.kind = Term::Or;  op = __dfsan::Or;  break;
      default: t.kind = Term::Xor; op = __dfsan::Xor; break;
    }
    // A constant operand goes on the LEFT, always.  That is not a
    // simplification: And/Or/Xor are commutative, so __taint_union() swaps when
    // l1 > l2, and a constant's label is 0 -- it can only ever arrive as l1.
    // find_roots' arms are written to that invariant and reject ("null child")
    // if the constant shows up on the right.
    //
    // OFF by default (--const-pct 0) because a trace cannot carry this exact
    // shape: __taint_union() folds every constant boolean connective away
    // before it ever builds a label -- 0&x, 0|x, 0^x, 1&x, 1|x, and 1^x, which
    // becomes Not.  All six, so nothing gets through.
    //
    // What it does reproduce is the *node* those connectives fold to, an
    // rgd::Bool sitting below the root of find_roots' output, and that one is
    // reachable: an ICmp leaf whose two operand subtrees both exceed
    // max_ast_size gets concretized to a Bool carrying the value the run
    // observed (see the concrete_ops == 3 arm), and so does the icmp arm with a
    // nested comparison on both sides.  It measured 0 times in 4.47M libpng
    // conditions -- rare, not impossible -- so this generator is how the
    // property gets tested at all.
    //
    // Both failure modes below were real, and both came from one leak (#130):
    // the bool-icmp arm wrapped a Bool child in LNot instead of folding it,
    // which is the one arm of find_roots that did not maintain "no Bool below
    // the root".
    //
    //   --const-pct 10 --depth 5 --cases 5000 --seed 1:
    //   unsound=3 lossy=2 incomplete=36
    //
    //   INCOMPLETE  `(bcmp-not (and false L0))` -- the bool-icmp arm rewrites
    //               its parent to LNot over a Bool child, and to_nnf refuses
    //               the whole condition with "unexpected node kind".
    //   LOSSY       every conjunct of some clause hits the same refusal, so
    //               construct_task builds nothing and the clause is dropped.
    //               A DNF missing a disjunct is *narrower* than the formula:
    //               its solutions still flip the branch, there are just fewer
    //               of them.  Same class as refusing the condition outright.
    //   UNSOUND     `(or (bcmp-not (not (bcmp-not (and false L0))))
    //                    (not (not (not (xor L3 L1)))))` -- both clauses
    //               produce a task, but one of them lost the conjunct holding
    //               the Bool to "non-comparison root".  A clause is a
    //               conjunction, so dropping one conjunct *widens* it, and the
    //               task admits assignment 0x2, which does not reach the
    //               target direction.  The solver returns it and every
    //               consumer believes the branch flipped.
    //
    // The two directions come from two different sites, which is why both were
    // fixed: the Bool folds at the four negation sites stop the leak, and
    // construct_task's all-or-nothing arm contains the next one.  Measured
    // separately -- with the leak still in and only that arm, these runs give
    // unsound=0 with lossy=3/6/5, i.e. the widening route is gone and only the
    // narrowing one is left.  normalizer_oracle.test runs three --const-pct
    // configurations to keep both at zero.
    int lhs;
    if (pct(cfg_.const_pct)) {
      Term c;
      c.kind = Term::Const;
      c.value = static_cast<uint8_t>(rng_() & 1);
      lhs = emit(f, c);
    } else {
      lhs = gen_term(f, s, depth - 1);
    }
    // The rhs is built after the lhs, so its label is higher and l1 < l2 holds
    // without a swap -- again what the commutative canonicalization guarantees.
    int rhs = gen_term(f, s, depth - 1);
    t.a = lhs;
    t.b = rhs;
    t.label = build_connective(s, op, f.terms[lhs].label,
                               f.terms[lhs].kind == Term::Const ? f.terms[lhs].value : 0,
                               f.terms[rhs].label);
    return emit(f, t);
  }

  bool pct(uint32_t p) { return (rng_() % 100) < p; }

  std::mt19937_64 rng_;
  GenConfig cfg_;
};

// ---------------------------------------------------------------------------
// reading the DNF back out
// ---------------------------------------------------------------------------

struct Lit {
  int leaf;
  bool positive;
};
using Dnf = std::vector<std::vector<Lit>>;

bool dnf_eval(const Dnf &dnf, uint32_t mask) {
  for (const auto &clause : dnf) {
    bool all = true;
    for (const auto &l : clause) {
      if ((((mask >> l.leaf) & 1) != 0) != l.positive) { all = false; break; }
    }
    if (all) return true;
  }
  return false;
}

struct Stats {
  uint64_t checked = 0;
  // The two directions a DNF can disagree with the formula, split because they
  // are not equally bad and a single counter cannot answer "is this dangerous".
  //   unsound: the DNF admits an assignment the target rejects.  The solver can
  //            hand back an input that does NOT flip the branch, and every
  //            consumer believes it.  This is the one that must be zero.
  //   lossy:   the DNF rejects an assignment the target admits, i.e. solutions
  //            were dropped.  Coverage lost, nothing wrong believed -- the same
  //            class as refusing the condition outright, only silent about it.
  // Both fail the run: the parser should be exactly equivalent, and a lossy DNF
  // is still a defect worth a name.  Keeping them apart is what tells a missing
  // disjunct (a dropped clause) from a missing conjunct (a weakened clause).
  uint64_t unsound = 0;
  uint64_t lossy = 0;
  uint64_t incomplete = 0;
  uint64_t folded = 0;      // parser says the whole condition is a constant
  uint64_t arena_full = 0;  // refused because the rewrite did not fit
  uint64_t harness = 0;     // infrastructure, not a verdict: restart or
                            // retrieve_task itself failed
};

// ---------------------------------------------------------------------------
// one case
// ---------------------------------------------------------------------------

// @return false if this (formula, result) pair failed; already reported
bool check_one(const Formula &f, Store &store,
               const std::map<dfsan_label, int> &label_to_leaf,
               dfsan_label root_label, bool result, uint64_t seed, uint32_t idx,
               Stats &st, bool verbose, bool strict) {
  std::vector<uint8_t> buf(f.nleaves ? f.nleaves : 1, 0);
  std::vector<symsan::input_t> inputs{{buf.data(), buf.size()}};

  // A parser per case: the caches (root_expr_cache, constraint_cache,
  // ast_size_cache) are keyed by label, every case reuses labels from 1, and
  // restart() does not clear them -- so a shared parser would answer from the
  // previous case's table.
  // strict picks construct_task's policy for a conjunct that will not parse.
  // Both are worth running the oracle against, because they fail differently:
  // lenient hands out the weakened clause, so a regression shows as unsound=,
  // while strict drops it and the same regression shows as lossy=.  Neither is
  // exercised at all once find_roots stops leaking a Bool -- nothing in this
  // matrix reaches that arm -- so this is a guard for the next such leak.
  RGDAstParser parser(store.base(), store.bytes(), /*solve_nested=*/false,
                      /*max_ast_size=*/200, /*strict_clauses=*/strict);
  if (parser.restart(inputs) != 0) {
    printf("[case %u/%d] restart failed\n", idx, (int)result);
    st.harness++;
    return false;
  }

  std::vector<uint64_t> task_ids;
  int rc = parser.parse_cond(root_label, result, /*add_nested=*/false, task_ids);
  const std::string reason = parser.last_error();

  // parse_cond's target_direction is !result: the formula it solves for is the
  // one that FLIPS the branch.
  auto target = [&](uint32_t mask) { return result ? !f.eval(mask) : f.eval(mask); };
  const uint32_t nmask = 1u << f.nleaves;

  // Reports go to stdout, not stderr: the parser WARNFs its own prose on every
  // rejection, so a run is only readable with 2>/dev/null and the findings must
  // survive that.
  auto report = [&](const char *what, const char *detail) {
    printf("\n=== %s ===\n", what);
    printf("  seed %" PRIu64 " case %u  result=%d  root_label=%u  labels=%zu\n",
           seed, idx, (int)result, root_label, store.count());
    printf("  formula: ");
    f.print(stdout);
    printf("\n  reason: %s\n", reason.empty() ? "(none)" : reason.c_str());
    printf("  %s\n", detail);
  };

  if (task_ids.empty()) {
    if (reason == "cond folded to constant" ||
        reason == "cond folded against the branch") {
      // Legitimate only if the condition really is constant.  A wrong fold in a
      // SUBTERM propagates into the surviving formula and is caught by the
      // equivalence check below.  That is the case that matters: it is the
      // shape the set_boolvalue bug took (#127).
      bool v0 = f.eval(0);
      for (uint32_t m = 1; m < nmask; m++) {
        if (f.eval(m) != v0) {
          report("UNSOUND FOLD", "parser folded the condition to a constant, "
                                 "but it is not constant");
          st.unsound++;
          return false;
        }
      }
      // A wrong fold at the ROOT used to be invisible here -- parse_cond
      // returned 0 either way and never said which constant.  The two reasons
      // now say: parse_cond checks the folded value against `result`, the
      // direction the branch took, and renames the refusal when they disagree.
      // So the reason pins boolvalue(), and this matrix knows v0, and the two
      // must line up.  Either way round means the parser folded to the wrong
      // constant: "to constant" with v0 != result says it folded to `result`
      // when the formula says otherwise, and "against the branch" with
      // v0 == result says it folded away from a value the formula agrees with.
      //
      // Note this matrix enumerates BOTH truth values of `result` for every
      // formula, so for a constant formula one of the two pairs is a branch no
      // real program can produce -- which makes those cases free coverage of
      // the guard rather than something to skip.
      const bool contradicts = (v0 != result);
      if (contradicts != (reason == "cond folded against the branch")) {
        report("UNSOUND FOLD", contradicts
               ? "parser folded to the branch's direction, but the formula is "
                 "constant the other way"
               : "parser refused the fold as contradicting the branch, but the "
                 "formula's constant value agrees with it");
        st.unsound++;
        return false;
      }
      st.folded++;
      return true;
    }
    if (reason == "ast arena full") {
      // A refusal by name, not a wrong answer: the skeleton arena never grows
      // (AstNode::add_children returns nullptr at capacity), so a rewrite that
      // does not fit is declined rather than half-applied.  Counted so a run
      // where this dominates cannot look like a clean pass.
      st.arena_full++;
      return true;
    }
    report("INCOMPLETE", rc != 0 ? "parse_cond refused the formula"
                                 : "parse_cond produced no task");
    st.incomplete++;
    return false;
  }

  // read each task back as a clause of literals
  Dnf dnf;
  for (uint64_t id : task_ids) {
    auto task = parser.retrieve_task(id);
    if (task == nullptr) {
      report("HARNESS", "retrieve_task returned null");
      st.harness++;
      return false;
    }
    std::vector<Lit> clause;
    for (size_t i = 0; i < task->size(); i++) {
      const AstNode *croot = task->constraints(i)->get_root();
      auto itr = label_to_leaf.find(croot->label());
      if (itr == label_to_leaf.end()) {
        // to_dnf handed construct_task something that is not a relational leaf.
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "literal %zu has label %u, which is not one of the leaves",
                 i, croot->label());
        report("BAD LITERAL", detail);
        st.unsound++;
        return false;
      }
      // A literal's sign is in its comparison kind: to_nnf negates a leaf by
      // swapping the kind for its complement, so the leaf's own predicate means
      // positive and kPreds' hand-written complement means negative.  Anything
      // else is a wrong literal, and it is checked here rather than trusted
      // because a solver would act on it silently.
      const Pred *p = f.leaves[itr->second].pred;
      const uint32_t cmp = task->comparisons(i);
      bool positive;
      if (cmp == p->kind) positive = true;
      else if (cmp == p->neg) positive = false;
      else {
        char detail[192];
        snprintf(detail, sizeof(detail),
                 "literal %zu on L%d has comparison kind %u (%s), expected %s or %s",
                 i, itr->second, cmp, cmp < rgd::LastOp ? AstKindName[cmp] : "?",
                 AstKindName[p->kind], AstKindName[p->neg]);
        report("WRONG PREDICATE", detail);
        st.unsound++;
        return false;
      }
      clause.push_back(Lit{itr->second, positive});
    }
    dnf.push_back(std::move(clause));
  }

  // the check
  for (uint32_t mask = 0; mask < nmask; mask++) {
    bool want = target(mask);
    bool got = dnf_eval(dnf, mask);
    if (want == got) continue;
    char detail[256];
    snprintf(detail, sizeof(detail),
             "assignment 0x%x: formula=%d target=%d, but the DNF says %d\n"
             "  (%zu clause(s) from %zu task(s))",
             mask, (int)f.eval(mask), (int)want, (int)got, dnf.size(), task_ids.size());
    // got=1, want=0 is the dangerous direction: a solution to this DNF need not
    // flip the branch.  got=0, want=1 only means solutions were dropped.
    report(got ? "UNSOUND (DNF admits a non-flipping assignment)"
               : "LOSSY (DNF drops a flipping assignment)", detail);
    if (verbose) {
      for (size_t c = 0; c < dnf.size(); c++) {
        printf("    clause %zu:", c);
        for (const auto &l : dnf[c]) printf(" %sL%d", l.positive ? "" : "!", l.leaf);
        printf("\n");
      }
    }
    if (got) st.unsound++; else st.lossy++;
    return false;
  }

  st.checked++;
  return true;
}

void usage(const char *argv0) {
  fprintf(stderr,
      "usage: %s [options]\n"
      "  --seed N        PRNG seed (default 1)\n"
      "  --cases N       number of formulas (default 2000)\n"
      "  --leaves N      distinct relational leaves per formula, <= 16 (default 4)\n"
      "  --depth N       max formula depth (default 3)\n"
      "  --const-pct N   chance a connective takes a constant lhs (default 0;\n"
      "                  a shape __taint_union folds away before it reaches a\n"
      "                  label, kept because it reproduces the Bool node that\n"
      "                  concretization also produces -- see gen_term)\n"
      "  --boolcmp-pct N chance of a `bool ==/!= 0/1` layer (default 15)\n"
      "  --strict        drop a whole DNF clause when one conjunct will not\n"
      "                  parse, instead of handing out the weakened clause\n"
      "                  (construct_task's strict_clauses; default is lenient,\n"
      "                  which is what the fuzzer runs)\n"
      "  --stop-first    exit on the first failure\n"
      "  -v              dump the DNF on a soundness failure\n",
      argv0);
}

} // namespace

int main(int argc, char **argv) {
  uint64_t seed = 1;
  uint32_t cases = 2000;
  GenConfig cfg;
  bool verbose = false;
  bool stop_first = false;
  bool strict = false;

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> const char * {
      if (i + 1 >= argc) { usage(argv[0]); exit(2); }
      return argv[++i];
    };
    if (a == "--seed") seed = strtoull(next(), nullptr, 0);
    else if (a == "--cases") cases = (uint32_t)strtoul(next(), nullptr, 0);
    else if (a == "--leaves") cfg.nleaves = (uint32_t)strtoul(next(), nullptr, 0);
    else if (a == "--depth") cfg.depth = (uint32_t)strtoul(next(), nullptr, 0);
    else if (a == "--const-pct") cfg.const_pct = (uint32_t)strtoul(next(), nullptr, 0);
    else if (a == "--boolcmp-pct") cfg.boolcmp_pct = (uint32_t)strtoul(next(), nullptr, 0);
    else if (a == "--strict") strict = true;
    else if (a == "--stop-first") stop_first = true;
    else if (a == "-v") verbose = true;
    else { usage(argv[0]); return 2; }
  }
  if (cfg.nleaves < 1 || cfg.nleaves > 16) {
    fprintf(stderr, "--leaves must be in [1, 16]\n");
    return 2;
  }

  Stats st;
  uint64_t failed_cases = 0;

  for (uint32_t c = 0; c < cases; c++) {
    Formula f;
    Store store;
    // seeded per case, so a failing case is reproducible from its own index
    Gen gen(seed * 1000003u + c, cfg);
    gen.build(f, store);

    std::map<dfsan_label, int> label_to_leaf;
    for (const auto &t : f.terms) {
      if (t.kind == Term::LeafRef) label_to_leaf[t.label] = t.leaf;
    }
    dfsan_label root_label = f.terms[f.root].label;

    bool ok = true;
    for (bool result : {false, true}) {
      if (!check_one(f, store, label_to_leaf, root_label, result, seed, c, st, verbose,
                     strict)) {
        ok = false;
        if (stop_first) { failed_cases++; goto done; }
      }
    }
    if (!ok) failed_cases++;
  }
done:

  printf("NORM-SUMMARY cases=%u checked=%" PRIu64 " folded=%" PRIu64
         " arena_full=%" PRIu64 " unsound=%" PRIu64 " lossy=%" PRIu64
         " incomplete=%" PRIu64 " harness=%" PRIu64 "\n",
         cases, st.checked, st.folded, st.arena_full, st.unsound, st.lossy,
         st.incomplete, st.harness);

  // lossy counts as a failure too -- the parser owes exact equivalence, and a
  // silently narrowed DNF is a defect even though it cannot mislead a solver.
  // It is separate from unsound so that a regression here says which kind it is.
  uint64_t bad = st.unsound + st.lossy + st.incomplete + st.harness;
  if (bad) {
    printf("NORM-RESULT FAIL (%" PRIu64 " bad outcome(s) over %" PRIu64 " failing case(s))\n",
           bad, failed_cases);
    return 1;
  }
  if (st.checked == 0) {
    printf("NORM-RESULT VACUOUS (nothing was actually checked)\n");
    return 1;
  }
  printf("NORM-RESULT PASS\n");
  return 0;
}
