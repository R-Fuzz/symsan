// Replay jigsaw's serialized constraint corpus through SymSan's RGD solver, to
// measure the JIT function-cache hit rate.
//
// Why this exists.  solvers/jit-solver.cpp keys its compiled-function cache
// (fCache) on the AST itself -- hash() picks the bucket, isEqualAst confirms --
// and JIT compilation is jigsaw's dominant cost.  That cache is the reason
// constants live in Constraint::input_args instead of in the AST; see THE
// HASHING INVARIANT in include/ast.h.  So any change to the AST representation
// has to be checked against its hit rate, and doing that honestly needs many
// thousands of constraints from a real target.  The lit suite has nothing like
// that: its targets produce a handful of constraints each.
//
// Where the corpus comes from.  ../jigsaw is the research prototype this
// solver grew out of.  It is unmaintained -- every later change lives here --
// but it shipped a corpus of serialized constraints
// (tests/{objdump,size,sqlite}_reload) and a replay driver (ReplayLocal in
// rgd.cc), and the representation still lines up:
//   - jigsaw's rgd_op.h kinds 0..37 (Bool..Memcmp) are byte-identical to
//     rgd::AstKind 0..37, and the corpus uses only kinds in that range;
//   - jigsaw's jit.cc already loads constants from args[] rather than baking
//     them into the emitted code, which is exactly the property this cache
//     depends on.
//
// What does NOT carry over is the hashing.  The corpus stores each node's hash,
// but those are jigsaw's: its mapArgs folds children pairwise and takes a
// Read's hash from the LAST byte's slot, where parsers/rgd-parser.cpp folds
// (left, (kind << 16) | bits, right) and takes it from the first.  Every hash
// is therefore recomputed here with rgd-parser's rules.  Reusing the stored
// ones would measure jigsaw's cache, not ours.
//
// The corpus is protobuf (../jigsaw/rgd.proto, message JitCmdv2, records
// length-delimited by a varint).  SymSan has no protobuf dependency and this
// does not add one: the two messages needed are read by the wire-format reader
// below.  That is deliberate -- the old NEED_OFFLINE serializer in
// rgd-parser.cpp rotted into something that would not compile precisely
// because it depended on a protobuf API that moved.
//
// Usage: rgdreplay [options] <dir>...
//   --limit N        stop after N solve records (0 = no limit, the default)
//   --files N        read at most N files per directory (0 = no limit)
//   --no-cons-cache  do not reuse a Constraint across records by label, so
//                    every constraint reaches the AST cache.  The default
//                    keeps the label cache, which is what production does.
//   --solve          also run the gradient-descent search (slow; the cache
//                    numbers do not need it)
//   --hash-const-values
//                    fold each constant's VALUE into its hash, instead of only
//                    its width and argument index.  This is the design the AST
//                    deliberately does not use -- it is what you get if
//                    constants are baked into the JIT'ed function rather than
//                    passed through args[] -- so the drop in hit rate against a
//                    default run is the measured worth of THE HASHING
//                    INVARIANT.  Diagnostic only: the emitted code is unchanged
//                    and still reads args[], so the extra functions really are
//                    redundant.

#include "ast.h"
#include "task.h"
#include "solver.h"

#include "dfsan/dfsan.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace rgd;

// The i2s solver (part of librgd-solver) references the global
// __dfsan::get_label_info.  This driver never runs i2s -- it builds ASTs from
// the corpus, not from a union table -- but the symbol must resolve for the
// link to succeed; provide a stub that fails loudly if ever reached.
namespace __dfsan {
dfsan_label_info* get_label_info(dfsan_label label) {
  (void)label;
  throw std::runtime_error("get_label_info is not available in rgdreplay");
}
} // namespace __dfsan

namespace {

// -------------------------------------------------------------------------
// protobuf wire format
// -------------------------------------------------------------------------

namespace pb {

struct Buf {
  const uint8_t *p = nullptr;
  const uint8_t *e = nullptr;
  bool empty() const { return p >= e; }
  size_t size() const { return (size_t)(e - p); }
};

enum { WT_VARINT = 0, WT_64BIT = 1, WT_LEN = 2, WT_32BIT = 5 };

bool read_varint(Buf &b, uint64_t &out) {
  uint64_t r = 0;
  int s = 0;
  while (b.p < b.e) {
    uint8_t c = *b.p++;
    r |= (uint64_t)(c & 0x7f) << s;
    if (!(c & 0x80)) { out = r; return true; }
    s += 7;
    if (s >= 64) return false; // more than 10 continuation bytes
  }
  return false;
}

struct Field {
  uint32_t num = 0;
  uint32_t wire = 0;
  uint64_t varint = 0; // set for WT_VARINT
  Buf len;             // set for WT_LEN
};

// Read one field. Returns false at a malformed record; callers loop on
// !b.empty() so a clean end of buffer is not an error.
bool next_field(Buf &b, Field &f) {
  uint64_t key;
  if (!read_varint(b, key)) return false;
  f.num = (uint32_t)(key >> 3);
  f.wire = (uint32_t)(key & 7);
  switch (f.wire) {
    case WT_VARINT:
      return read_varint(b, f.varint);
    case WT_64BIT:
      if (b.size() < 8) return false;
      b.p += 8;
      return true;
    case WT_32BIT:
      if (b.size() < 4) return false;
      b.p += 4;
      return true;
    case WT_LEN: {
      uint64_t n;
      if (!read_varint(b, n)) return false;
      if ((uint64_t)b.size() < n) return false;
      f.len.p = b.p;
      f.len.e = b.p + n;
      b.p += n;
      return true;
    }
    default:
      return false; // groups (3/4) never appear in proto3
  }
}

} // namespace pb

// -------------------------------------------------------------------------
// AstNode as the corpus stores it
// -------------------------------------------------------------------------

struct ProtoAst {
  uint32_t kind = 0, bits = 0, index = 0, label = 0;
  uint32_t sessionid = 0, direction = 0, full = 0;
  uint32_t boolvalue = 0; // only on a folded Bool leaf
  uint64_t value = 0; // constant value / Read initial value, if present
  std::vector<ProtoAst> children;
};

// AstNode.value is a decimal string -- jigsaw wrote it with APInt, and it is
// how both a constant and a Read's initial byte values arrive.  The widest in
// the corpus is 20 digits, i.e. a full 64-bit value, so strtoull suffices.
bool parse_decimal(const pb::Buf &b, uint32_t bits, uint64_t &out) {
  char tmp[32];
  size_t n = b.size();
  if (n == 0 || n >= sizeof(tmp)) return false;
  memcpy(tmp, b.p, n);
  tmp[n] = 0;
  bool neg = tmp[0] == '-';
  errno = 0;
  char *end = nullptr;
  uint64_t v = strtoull(neg ? tmp + 1 : tmp, &end, 10);
  if (errno != 0 || end == tmp || *end != 0) return false;
  if (neg) v = (uint64_t)(-(int64_t)v);
  if (bits > 0 && bits < 64) v &= (1ULL << bits) - 1;
  out = v;
  return true;
}

bool parse_ast(pb::Buf b, ProtoAst &n, int depth) {
  if (depth > 128) return false; // the corpus is 2 deep; this is a guard
  pb::Buf value_field;
  while (!b.empty()) {
    pb::Field f;
    if (!pb::next_field(b, f)) return false;
    switch (f.num) {
      case 1: n.kind = (uint32_t)f.varint; break;
      case 2: n.boolvalue = f.varint ? 1 : 0; break; // folded Bool leaf only
      case 3: n.bits = (uint32_t)f.varint; break;
      case 4: value_field = f.len; break;
      case 5:
        n.children.emplace_back();
        if (!parse_ast(f.len, n.children.back(), depth + 1)) return false;
        break;
      case 7: n.index = (uint32_t)f.varint; break;
      case 8: n.label = (uint32_t)f.varint; break;
      case 10: n.direction = (uint32_t)f.varint; break;
      case 11: n.sessionid = (uint32_t)f.varint; break;
      case 12: n.full = (uint32_t)f.varint; break;
      default: break; // 6 (name) and 9 (hash) are deliberately ignored
    }
  }
  if (value_field.p) parse_decimal(value_field, n.bits, n.value);
  return true;
}

struct Record {
  uint32_t cmd = 0; // 1 = cache this expression only, 2 = solve
  std::vector<ProtoAst> exprs;
};

bool parse_record(pb::Buf b, Record &r) {
  while (!b.empty()) {
    pb::Field f;
    if (!pb::next_field(b, f)) return false;
    switch (f.num) {
      case 1: r.cmd = (uint32_t)f.varint; break;
      case 3: // expr_string: a serialized AstNode, one per repeated entry
      case 8: // expr: the same thing as a nested message (unused in the files)
        r.exprs.emplace_back();
        if (!parse_ast(f.len, r.exprs.back(), 0)) return false;
        break;
      default: break; // test_value, file_name, bhash, shash, direction
    }
  }
  return true;
}

// -------------------------------------------------------------------------
// lowering: ProtoAst -> rgd::Constraint, with rgd-parser.cpp's hashes
// -------------------------------------------------------------------------

uint32_t count_nodes(const ProtoAst &n) {
  uint32_t s = 1;
  for (const auto &c : n.children) s += count_nodes(c);
  return s;
}

// Upper bound on input_args slots, so the vector is sized once -- the same
// thing scan_labels' arg_size_cache does on the live parse path.
uint32_t count_args(const ProtoAst &n) {
  uint32_t s = 0;
  if (n.kind == Constant) s = 1;
  else if (n.kind == Read) s = n.bits / 8;
  for (const auto &c : n.children) s += count_args(c);
  return s;
}

// Mirror rgd-parser.cpp's map_arg(): one input_args slot per input byte,
// deduped through local_map, the shape on the first byte, and the node hash
// taken from the FIRST byte's slot.
uint32_t map_arg(Constraint &c, uint32_t offset, uint32_t length, uint64_t iv) {
  uint32_t hash = 0;
  for (uint32_t i = 0; i < length; ++i, ++offset, iv >>= 8) {
    uint32_t arg_index;
    auto itr = c.local_map.find(offset);
    if (itr == c.local_map.end()) {
      arg_index = (uint32_t)c.input_args.size();
      c.inputs.insert({offset, (uint8_t)(iv & 0xff)});
      c.local_map[offset] = arg_index;
      c.input_args.push_back(std::make_pair(true, 0)); // gidx filled by finalize
    } else {
      arg_index = itr->second;
    }
    if (i == 0) {
      c.shapes[offset] = length;
      hash = xxhash(length * 8, Read, arg_index);
    } else {
      c.shapes[offset] = 0;
    }
  }
  return hash;
}

// see --hash-const-values; read by lower_node, which has no Options in hand
bool g_hash_const_values = false;

// How many constant nodes were lowered, and how many DISTINCT (width, value)
// pairs they took.  The ratio is what decides whether keeping constants out of
// the JIT'ed function is worth anything on a given target: one shape compared
// against one constant reuses nothing, one shape against many constants is the
// whole point.
uint64_t g_const_nodes = 0;
std::unordered_map<uint64_t, uint64_t> g_const_values;

// Why a tree could not be lowered.  Worth counting per reason rather than in
// one bucket: each of these means something different about the corpus, and
// lumping them together is how a representation gap hides as "some failures".
enum LowerFail {
  LF_NONE = 0,
  LF_KIND,       // kind outside rgd::AstKind, or a width that does not fit
  LF_CONSTANT,   // constant wider than a slot, or with children
  LF_READ,       // read width not a whole number of bytes
  LF_NULLARY,    // an interior kind that arrived with no children
  LF_ARITY,      // more than the two children an AstNode holds
  LF_BUDGET,     // add_children() hit the reserved capacity
  LF_MAX
};
struct LowerDiag {
  int reason = LF_NONE;
  uint32_t kind = 0;   // the offending node's kind, for the report
  uint32_t bits = 0;
};

const char *lower_fail_name(int f) {
  switch (f) {
    case LF_KIND: return "unknown kind/width";
    case LF_CONSTANT: return "constant";
    case LF_READ: return "read width";
    case LF_NULLARY: return "no children";
    case LF_ARITY: return "arity > 2";
    case LF_BUDGET: return "node budget";
    default: return "none";
  }
}

bool lower_node(const ProtoAst &n, const std::shared_ptr<Constraint> &c,
                AstNode *out, LowerDiag &d) {
  if (n.kind >= LastOp) { d = {LF_KIND, n.kind, n.bits}; return false; }
  if (n.bits > UINT16_MAX) { d = {LF_KIND, n.kind, n.bits}; return false; }
  out->set_kind((uint16_t)n.kind);
  out->set_bits((uint16_t)n.bits);
  out->set_label(n.label);
  c->ops[n.kind] = true;

  if (n.kind == Bool) {
    // A folded boolean constant: the parser evaluated a comparison whose
    // operands were all concrete and left the answer here.  It is a LEAF, not
    // a nested-constraint reference -- those are the full=0 stubs, resolved
    // one level up.
    //
    // Unlike a Constant, this value is NOT read through args[]: jit.cc bakes
    // it into the emitted code as getTrue/getFalse.  So by THE HASHING
    // INVARIANT it has to be folded into the hash, or true and false share one
    // compiled function.
    //
    // set_boolvalue() used to store the complement of what it was given, so
    // this passed the complement to get the corpus's bit back out.  That is
    // fixed in ast.h now -- the setter and boolvalue()'s readers (jit.cc,
    // z3-solver.cpp) agree -- so hand it the bit itself.
    out->set_boolvalue(n.boolvalue);
    out->set_hash(xxhash(n.bits, Bool, n.boolvalue));
    return true;
  }
  if (n.kind == Constant) {
    if (n.bits > 64 || !n.children.empty()) { d = {LF_CONSTANT, n.kind, n.bits}; return false; }
    uint32_t arg_index = (uint32_t)c->input_args.size();
    out->set_index(arg_index);
    c->input_args.push_back(std::make_pair(false, n.value));
    c->const_num += 1;
    g_const_nodes++;
    g_const_values[((uint64_t)n.bits << 56) ^ n.value]++;
    out->set_hash(g_hash_const_values ? xxhash(n.bits, Constant, n.value)
                                      : xxhash(n.bits, Constant, arg_index));
    return true;
  }
  if (n.kind == Read) {
    if (n.bits == 0 || (n.bits % 8) != 0 || !n.children.empty()) {
      d = {LF_READ, n.kind, n.bits};
      return false;
    }
    out->set_index(n.index);
    out->set_hash(map_arg(*c, n.index, n.bits / 8, n.value));
    return true;
  }
  if (n.children.empty()) { d = {LF_NULLARY, n.kind, n.bits}; return false; }
  if (n.children.size() > 2) { d = {LF_ARITY, n.kind, n.bits}; return false; }

  AstNode *left = out->add_children();
  if (!left) { d = {LF_BUDGET, n.kind, n.bits}; return false; }
  if (!lower_node(n.children[0], c, left, d)) return false;

  if (n.children.size() == 1) {
    // unary; Extract's starting bit rides in index(), same as the parser
    out->set_index(n.index);
    out->set_hash(xxhash(n.bits, out->kind(), left->hash()));
    return true;
  }

  AstNode *right = out->add_children();
  if (!right) { d = {LF_BUDGET, n.kind, n.bits}; return false; }
  if (!lower_node(n.children[1], c, right, d)) return false;
  // jigsaw does not care which relational operator it is, as long as the
  // operands match, so relational kinds all hash as Bool -- see the binary
  // case in rgd-parser.cpp's do_uta_rel().
  uint32_t kind = isRelationalKind(out->kind()) ? (uint32_t)Bool
                                                : (uint32_t)out->kind();
  out->set_hash(xxhash(left->hash(), (kind << 16) | out->bits(), right->hash()));
  return true;
}

std::shared_ptr<Constraint> lower(const ProtoAst &n, LowerDiag &d) {
  auto c = std::make_shared<Constraint>(count_nodes(n), count_args(n));
  // op1/op2 are the traced comparison operands; the corpus does not carry
  // them, and jigsaw recomputes what it needs from the JIT'ed function.
  c->op1 = 0;
  c->op2 = 0;
  if (!lower_node(n, c, c->ast.get(), d)) return nullptr;
  return c;
}

// -------------------------------------------------------------------------
// replay
// -------------------------------------------------------------------------

struct Options {
  uint64_t limit = 0;
  uint64_t files = 0;
  bool cons_cache = true;
  bool solve = false;
  bool hash_const_values = false;
};

struct Counters {
  uint64_t files = 0, records = 0, cache_only = 0, solve_records = 0;
  uint64_t tasks = 0, constraints = 0;
  uint64_t cons_hits = 0, cons_misses = 0;
  uint64_t unresolved_nested = 0, non_relational = 0, lower_failed = 0;
  uint64_t malformed = 0;
  uint64_t sat = 0, unsat = 0, timeout = 0, error = 0, jit_failed = 0;
  uint64_t lower_reason[LF_MAX] = {};
  // kinds seen on a lowering failure, so an unsupported op shows up by name
  // rather than as a count
  std::unordered_map<uint32_t, uint64_t> lower_kind;
};

// The full=1 expressions, keyed the way jigsaw's nestCache keys them -- except
// that jigsaw computed sessionid * 10000 + label, which collides as soon as a
// session has 10000 labels (these corpora reach six figures).  A collision
// hands back the wrong tree, so pack the two fields instead.
using NestKey = uint64_t;
NestKey nest_key(const ProtoAst &n) {
  return ((uint64_t)n.sessionid << 32) | n.label;
}

// The whole-Constraint cache, keyed like jigsaw's consCache: the same label in
// the same session at the same kind is the same constraint, so it keeps its
// JIT'ed function and never reaches the AST cache.  This is the analogue of
// rgd-parser.cpp's constraint_cache, and leaving it on is what production
// does; --no-cons-cache turns it off to see the AST cache unmasked.
struct ConsKey {
  uint32_t sessionid, label, kind;
  bool operator==(const ConsKey &o) const {
    return sessionid == o.sessionid && label == o.label && kind == o.kind;
  }
};
struct ConsKeyHash {
  size_t operator()(const ConsKey &k) const {
    return xxhash(k.sessionid, k.label, k.kind);
  }
};

class Replayer {
public:
  Replayer(const Options &opt, JITSolver *solver) : opt_(opt), solver_(solver) {}

  const Counters &counters() const { return n_; }

  bool done() const { return opt_.limit && n_.solve_records >= opt_.limit; }

  void run_dir(const std::string &dir) {
    std::vector<std::filesystem::path> paths;
    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
      if (entry.is_regular_file()) paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end()); // deterministic order
    uint64_t nfiles = 0;
    for (const auto &p : paths) {
      if (opt_.files && nfiles >= opt_.files) break;
      if (done()) break;
      run_file(p.string());
      nfiles++;
      n_.files++;
      if ((nfiles % 25) == 0) {
        fprintf(stderr, "\r  %s: %lu files, %lu solve records",
                dir.c_str(), nfiles, n_.solve_records);
        fflush(stderr);
      }
    }
    fprintf(stderr, "\r  %s: %lu files, %lu solve records\n",
            dir.c_str(), nfiles, n_.solve_records);
  }

private:
  void run_file(const std::string &path) {
    std::vector<uint8_t> data;
    if (!slurp(path, data)) {
      fprintf(stderr, "cannot read %s\n", path.c_str());
      return;
    }
    pb::Buf b{data.data(), data.data() + data.size()};
    while (!b.empty() && !done()) {
      uint64_t n;
      if (!pb::read_varint(b, n)) { n_.malformed++; return; }
      if ((uint64_t)b.size() < n) { n_.malformed++; return; }
      pb::Buf rec{b.p, b.p + n};
      b.p += n;
      Record r;
      if (!parse_record(rec, r)) { n_.malformed++; continue; }
      n_.records++;
      run_record(r);
    }
  }

  void run_record(const Record &r) {
    // Every full=1 expression is cached first, whatever the command: a later
    // record's full=0 stub is only a (sessionid, label) reference back to one,
    // and cmd=1 records exist purely to populate this.  The trees have to
    // outlive the record they arrived in, hence the copy.
    for (const auto &e : r.exprs) {
      if (e.full != 1) continue;
      auto key = nest_key(e);
      if (!nest_store_.count(key))
        nest_store_[key] = std::make_shared<ProtoAst>(e);
    }
    if (r.cmd != 2) { n_.cache_only++; return; }
    n_.solve_records++;

    auto task = std::make_shared<SearchTask>();
    for (const auto &e : r.exprs) {
      const ProtoAst *node = &e;
      if (e.full != 1) {
        auto itr = nest_store_.find(nest_key(e));
        if (itr == nest_store_.end()) { n_.unresolved_nested++; continue; }
        node = itr->second.get();
      }
      if (!isRelationalKind((uint16_t)node->kind)) { n_.non_relational++; continue; }
      // direction 1 means the branch went that way, so the constraint to solve
      // is the negation.  Which relational kind it is does not affect the AST
      // cache -- they all hash as Bool -- but it does affect the search.
      uint32_t comparison = node->direction ? node->kind
                                            : negate_cmp((uint16_t)node->kind);
      auto c = get_constraint(*node);
      if (!c) continue;
      task->add_constraint(c, comparison);
      n_.constraints++;
    }
    if (task->empty()) return;
    task->finalize();
    n_.tasks++;

    if (!opt_.solve) {
      if (!solver_->jit_constraints(task)) n_.jit_failed++;
      return;
    }
    size_t max_off = 0;
    for (const auto &[offset, value] : task->inputs())
      if (offset > max_off) max_off = offset;
    size_t in_size = max_off + 1;
    // out_ gets room above in_size because a solver may answer with a longer
    // input than it was handed -- a strlen satisfied by inserting bytes.
    if (in_.size() < in_size) {
      in_.resize(in_size, 0);
      out_.resize(in_size + 4096, 0);
    }
    size_t out_size = 0;
    switch (solver_->solve(task, in_.data(), in_size, out_.data(), out_size)) {
      case SOLVER_SAT: n_.sat++; break;
      case SOLVER_UNSAT: n_.unsat++; break;
      case SOLVER_TIMEOUT: n_.timeout++; break;
      default: n_.error++; break;
    }
  }

  std::shared_ptr<Constraint> get_constraint(const ProtoAst &node) {
    ConsKey key{node.sessionid, node.label, node.kind};
    if (opt_.cons_cache) {
      auto itr = cons_cache_.find(key);
      if (itr != cons_cache_.end()) { n_.cons_hits++; return itr->second; }
      n_.cons_misses++;
    }
    LowerDiag d;
    auto c = lower(node, d);
    if (!c) {
      n_.lower_failed++;
      n_.lower_reason[d.reason]++;
      n_.lower_kind[d.kind]++;
      return nullptr;
    }
    if (opt_.cons_cache) cons_cache_[key] = c;
    return c;
  }

  static bool slurp(const std::string &path, std::vector<uint8_t> &out) {
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
      out.insert(out.end(), buf, buf + n);
    fclose(f);
    return true;
  }

  Options opt_;
  JITSolver *solver_;
  Counters n_;
  std::unordered_map<NestKey, std::shared_ptr<ProtoAst>> nest_store_;
  std::unordered_map<ConsKey, std::shared_ptr<Constraint>, ConsKeyHash> cons_cache_;
  std::vector<uint8_t> in_, out_;
};

double pct(uint64_t hit, uint64_t total) {
  return total ? 100.0 * (double)hit / (double)total : 0.0;
}

} // namespace

int main(int argc, char **argv) {
  Options opt;
  std::vector<std::string> dirs;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--limit" && i + 1 < argc) opt.limit = strtoull(argv[++i], nullptr, 10);
    else if (a == "--files" && i + 1 < argc) opt.files = strtoull(argv[++i], nullptr, 10);
    else if (a == "--no-cons-cache") opt.cons_cache = false;
    else if (a == "--solve") opt.solve = true;
    else if (a == "--hash-const-values") opt.hash_const_values = true;
    else if (a.rfind("--", 0) == 0) {
      fprintf(stderr, "unknown option %s\n", a.c_str());
      return 1;
    } else dirs.push_back(a);
  }
  if (dirs.empty()) {
    fprintf(stderr,
            "Usage: %s [--limit N] [--files N] [--no-cons-cache] [--solve] <dir>...\n",
            argv[0]);
    return 1;
  }

  g_hash_const_values = opt.hash_const_values;
  if (opt.hash_const_values)
    printf("constants hashed BY VALUE (invariant deliberately broken)\n");

  JITSolver solver;
  Replayer replayer(opt, &solver);
  for (const auto &d : dirs) {
    if (replayer.done()) break;
    replayer.run_dir(d);
  }

  const Counters &n = replayer.counters();
  printf("corpus: %lu files, %lu records (%lu solve, %lu cache-only)\n",
         n.files, n.records, n.solve_records, n.cache_only);
  printf("tasks: %lu, constraints: %lu\n", n.tasks, n.constraints);
  if (opt.cons_cache) {
    printf("constraint cache (label): hits %lu misses %lu (%.1f%% hit)\n",
           n.cons_hits, n.cons_misses, pct(n.cons_hits, n.cons_hits + n.cons_misses));
  } else {
    printf("constraint cache (label): disabled\n");
  }
  printf("dropped: unresolved nested %lu, non-relational %lu, lowering failed %lu,"
         " malformed records %lu\n",
         n.unresolved_nested, n.non_relational, n.lower_failed, n.malformed);
  if (n.lower_failed) {
    for (int i = 1; i < LF_MAX; i++) {
      if (n.lower_reason[i])
        printf("  lowering failed, %s: %lu\n", lower_fail_name(i), n.lower_reason[i]);
    }
    std::vector<std::pair<uint64_t, uint32_t>> kinds;
    for (const auto &[k, v] : n.lower_kind) kinds.push_back({v, k});
    std::sort(kinds.rbegin(), kinds.rend());
    for (const auto &[v, k] : kinds) {
      printf("  lowering failed, kind %u (%s): %lu\n", k,
             k < LastOp ? AstKindName[k] : "?", v);
    }
  }
  if (opt.solve) {
    printf("solve: sat %lu unsat %lu timeout %lu error %lu\n",
           n.sat, n.unsat, n.timeout, n.error);
  } else {
    printf("jit: %lu tasks rejected by codegen\n", n.jit_failed);
  }
  printf("constants: %lu nodes, %zu distinct (width, value) pairs\n",
         g_const_nodes, g_const_values.size());
  solver.print_stats(1);
  return 0;
}
