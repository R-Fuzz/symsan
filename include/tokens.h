/*
  symsan::TokenCollector -- the concrete bytes the target compared its input
  against, as a fuzzer dictionary.

  A concolic engine sees every comparison the target performs, including the
  ones it cannot solve.  AFL++'s LTO autodict reads compile-time constants out
  of the binary; the half it cannot reach is the *runtime* comparand -- a name
  interned while parsing an earlier part of the input, a table entry, a length
  derived from a header field.  Those are exactly what shows up here.

  Deliberately independent of the parser and of the solving decision.  A
  condition parse_cond() refuses -- over max_ast_size, or built from an operator
  the parser does not model -- is precisely the one whose constants are worth
  handing to a token mutator, so collection happens on the raw union table
  before anything decides whether the branch became a task.

  (c) 2023 - 2026 by Chengyu Song <csong@cs.ucr.edu>
  License: Apache 2.0
*/

#pragma once

#include "dfsan/dfsan.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>
#include <unordered_set>
#include <vector>

namespace symsan {

class TokenCollector {
public:
  /// A concrete byte string the target compared its input against.  @c data is
  /// collector-owned and stays valid for the life of the collector.
  struct Token {
    const uint8_t *data;
    size_t size;
  };

  // Shortest and longest token worth keeping.  The floor is AFL++'s: a one-byte
  // token is not a dictionary entry, it is a byte flip, and havoc already covers
  // the whole byte space for free.  The ceiling matches MAX_AUTO_EXTRA, so a
  // memcmp over a whole buffer contributes its head rather than nothing.
  static constexpr size_t kMinTokenSize = 2;
  static constexpr size_t kMaxTokenSize = 32;

  // How many nodes scan_cond() will look at for one condition.  Deliberately
  // not max_ast_size: that gate is what makes the parser give up, and a
  // condition the parser gave up on is one whose constants are worth having.
  static constexpr size_t kScanBudget = 256;

  /// Point the collector at the union table so scan_cond() can walk it.
  /// @param label_base   base of the shared union table
  /// @param table_bytes  its size in bytes
  /// @param max_tokens   hard cap on distinct tokens, 0 for the default
  void init(void *label_base, size_t table_bytes, size_t max_tokens = 0) {
    label_base_ = static_cast<dfsan_label_info *>(label_base);
    label_count_ = table_bytes / sizeof(dfsan_label_info);
    if (max_tokens) max_tokens_ = max_tokens;
  }

  /// Intern @p size bytes at @p buf, if they pass the filters.
  void add(const uint8_t *buf, size_t size) {
    if (size < kMinTokenSize) return;
    if (size > kMaxTokenSize) size = kMaxTokenSize;
    // A hard cap rather than an eviction policy.  A dictionary is diluted by its
    // size -- a token mutator draws one uniformly at random -- so the failure
    // mode of an unbounded dictionary is not memory, it is that the useful
    // entries stop being picked.  Keeping the first N also keeps the ones the
    // seed corpus found, which are the ones nearest the code already reached.
    if (tokens_.size() >= max_tokens_) return;
    auto res = tokens_.emplace(reinterpret_cast<const char *>(buf), size);
    if (res.second) new_tokens_.push_back(&*res.first);
  }

  /// Intern @p size bytes at @p buf, dropping one trailing NUL.
  ///
  /// For a comparand the runtime shipped from a str*/mem* wrapper.  A C string
  /// literal is compared including its terminator, so xmlStrEqual(name,
  /// "ENTITY") ships seven bytes -- but the NUL is the *parser's*, written when
  /// it copied the name out of the buffer, and no file has to contain one for
  /// the compare to succeed.  Handing "ENTITY\0" to a token mutator would splice
  /// a NUL into every XML file it fired on.
  void add_str(const uint8_t *buf, size_t size) {
    if (size && buf[size - 1] == 0) --size;
    add(buf, size);
  }

  /// Intern the low @p width bytes of @p value, in both byte orders.
  void add_int(uint64_t value, unsigned width) {
    // One byte is dropped by the size floor in add() anyway; i128 arrives as a
    // WideConst leaf and never reaches here with a value in op1/op2.
    if (width < kMinTokenSize || width > 8) return;
    // Small magnitudes are havoc's arithmetic mutator's job, not a dictionary's,
    // and there are enough of them to crowd out everything else.
    if (value < 256) return;
    if (uniform_bytes(value, width)) return;

    uint8_t le[8], be[8];
    for (unsigned i = 0; i < width; ++i) {
      le[i] = (uint8_t)((value >> (i * 8)) & 0xff);
      be[width - 1 - i] = le[i];
    }
    // Both orders, because the constant in the compare is in host order and the
    // bytes in the file may not be: a target that does ntohl(x) == 0x89504e47
    // holds the reverse on disk, and the swap is under the comparison rather
    // than in it.  Which one is right *is* readable from the AST -- a bswap
    // below the symbolic operand settles it -- but a token that never matches
    // costs one draw, while a missing one costs the branch.
    add(le, width);
    if (memcmp(le, be, width) != 0) add(be, width);
  }

  /// Resolve @p label to the single input byte it reads, through the casts C's
  /// integer promotion puts between a byte load and the comparison.
  /// @return false if it reads anything other than exactly one input byte
  bool single_byte_source(dfsan_label label, uint32_t *input_id,
                          uint64_t *offset) const {
    // Bounded because a malformed table would otherwise be a hang, and because
    // a legitimate chain is one or two casts deep.
    for (int depth = 0; depth < 8; ++depth) {
      if (label == CONST_LABEL || label >= label_count_) return false;
      const dfsan_label_info *info = &label_base_[label];
      const uint16_t op = info->op & 0xff;
      if (op == 0) {
        // a raw input byte: op1 is the offset, op2 the stream it came from
        *offset = info->op1.i;
        *input_id = (uint32_t)info->op2.i;
        return true;
      }
      if (op == __dfsan::Load) {
        // l2 is the byte count; anything wider is a word, not a character
        if (info->l2 != 1) return false;
        label = info->l1;
        continue;
      }
      if (op == __dfsan::ZExt || op == __dfsan::SExt || op == __dfsan::Trunc ||
          op == __dfsan::BitCast) {
        label = info->l1;
        continue;
      }
      return false;
    }
    return false;
  }

  /// How many input bytes @p label is a plain byte image of, or 0 when it is
  /// not one.
  ///
  /// A wide constant in a comparison is only a *file* literal when the value it
  /// is compared against reached the comparison as bytes: `ntohl(tag) ==
  /// 0x49484452` puts "IHDR" in the file, but `pos + 4 == len` puts nothing
  /// there at all.  The two are indistinguishable from the constant -- both are
  /// a 32-bit number -- and distinguishable from the AST, because the second
  /// has arithmetic under it and the first does not.
  ///
  /// Measured on libxml2 this is the whole difference between a dictionary and
  /// noise: without the rule 650 of 845 collected tokens were size_t
  /// comparisons -- buffer positions, lengths and counters -- and no byte
  /// string placed in an XML file can ever make one of them match.
  ///
  /// Loads, casts, Extract and Concat are permitted because they only move and
  /// resize bytes; that also covers bswap, which the runtime decomposes into
  /// size Extracts and size-1 Concats (see the note at dfsan.h:259) and which is
  /// exactly the byte-order case the rule has to keep.
  size_t image_width(dfsan_label label) const {
    // Small and fixed: an image is a handful of nodes, and a subtree that needs
    // more than this to describe how bytes were rearranged is not one worth
    // handing to a mutator.
    static constexpr size_t kImageBudget = 64;
    dfsan_label stack[kImageBudget];
    dfsan_label seen[kImageBudget];
    size_t sp = 0, nseen = 0, bytes = 0;
    stack[sp++] = label;

    while (sp > 0) {
      dfsan_label l = stack[--sp];
      // A concrete operand of a Concat is a byte the target filled in itself:
      // it contributes nothing to the image but does not disqualify it.
      if (l == CONST_LABEL) continue;
      if (l >= label_count_) return 0;
      // The table is hash-consed, so one label is one subtree; bswap reaches the
      // same load eight times and its bytes must be counted once.
      bool dup = false;
      for (size_t i = 0; i < nseen; ++i) {
        if (seen[i] == l) { dup = true; break; }
      }
      if (dup) continue;
      if (nseen == kImageBudget) return 0;
      seen[nseen++] = l;

      const dfsan_label_info *info = &label_base_[l];
      const uint16_t op = info->op & 0xff;
      if (op == 0) {
        bytes += 1; // a raw input byte
        continue;
      }
      if (op == __dfsan::Load) {
        bytes += info->l2; // l2 is the byte count; the bytes are contiguous
        continue;
      }
      if (op == __dfsan::ZExt || op == __dfsan::SExt || op == __dfsan::Trunc ||
          op == __dfsan::BitCast || op == __dfsan::Extract) {
        if (sp == kImageBudget) return 0;
        stack[sp++] = info->l1;
        continue;
      }
      if (op == __dfsan::Concat) {
        if (sp + 2 > kImageBudget) return 0;
        stack[sp++] = info->l1;
        stack[sp++] = info->l2;
        continue;
      }
      return 0; // arithmetic, logic, a call -- not an image
    }
    return bytes;
  }

  /// Note that the target compared the input byte at @p offset against @p c.
  ///
  /// This is the channel a multi-byte comparand does not go through, and on a
  /// hand-written parser it is the only one there is: libxml2 spells `<!--` as
  /// `RAW == '<' && NXT(1) == '!' && NXT(2) == '-' && NXT(3) == '-'`, four
  /// separate i8 comparisons that no single condition contains.
  ///
  /// Runs are accumulated in *trace* order rather than gathered per input,
  /// because trace order is what separates one attempted construct from the
  /// next: the same offset gets compared against '<', then '&', then '%' as the
  /// parser tries each in turn, and a run keyed on the input alone would splice
  /// those into one nonsense string.  A comparison that does not continue the
  /// current run ends it.
  void note_byte_cmp(uint32_t input_id, uint64_t offset, uint8_t c) {
    if (input_id == run_input_ && offset == run_next_) {
      run_.push_back(c);
      run_next_ = offset + 1;
      if (run_.size() >= kMaxTokenSize) flush_run();
      return;
    }
    flush_run();
    run_input_ = input_id;
    run_next_ = offset + 1;
    run_.assign(1, c);
  }

  /// Walk the boolean skeleton of condition @p root and intern the constant
  /// operand of every integer comparison in it.
  void scan_cond(dfsan_label root) {
    if (!label_base_) return;
    // The union table is hash-consed, so one label is one distinct AST: a label
    // already walked this input has nothing new to say.
    if (!scanned_.insert(root).second) return;

    // Descend the boolean skeleton only -- And/Or/Xor/Not over comparisons --
    // and read the constant off each comparison.  Not a full AST walk: a
    // constant buried in arithmetic (the 0x10 in `x - 0x10 == 0`) is not the
    // value the file holds, while the operand of the comparison usually is.
    dfsan_label stack[kScanBudget];
    size_t sp = 0;
    size_t budget = kScanBudget;
    stack[sp++] = root;

    while (sp > 0 && budget-- > 0) {
      dfsan_label label = stack[--sp];
      if (label == CONST_LABEL || label >= label_count_) continue;
      dfsan_label_info *info = &label_base_[label];
      const uint16_t op = info->op & 0xff;

      if (op == __dfsan::ICmp) {
        // Exactly one side concrete.  Both concrete is a folded condition with
        // nothing to learn from; both symbolic has no constant at all.
        if (info->l1 == CONST_LABEL && info->l2 != CONST_LABEL) {
          add_cmp(info->op1.i, info->l2, info->op >> 8, info->size);
        } else if (info->l2 == CONST_LABEL && info->l1 != CONST_LABEL) {
          add_cmp(info->op2.i, info->l1, info->op >> 8, info->size);
        }
        continue;
      }
      if (op != __dfsan::And && op != __dfsan::Or && op != __dfsan::Xor &&
          op != __dfsan::Not) {
        continue;
      }
      // And/Or/Xor over wide integers are bit arithmetic, not a boolean
      // connective; only the i1 form is part of the skeleton.
      if (info->size != 1) continue;
      if (sp + 2 > kScanBudget) continue;
      if (info->l1 != CONST_LABEL) stack[sp++] = info->l1;
      if (info->l2 != CONST_LABEL) stack[sp++] = info->l2;
    }
  }

  /// One run of the target is over.  Labels, not tokens: the dictionary is
  /// deliberately cumulative, but a label only names the same AST within one
  /// run of the target.
  void end_input() {
    flush_run();
    scanned_.clear();
  }

  /// Drain up to @p max tokens found since the last call.  Anything past @p max
  /// is kept for the next one.
  /// @return how many tokens were written to @p out
  size_t take(Token *out, size_t max) {
    if (!out || max == 0) return 0;
    const size_t n = new_tokens_.size() < max ? new_tokens_.size() : max;
    for (size_t i = 0; i < n; ++i) {
      const std::string *s = new_tokens_[i];
      out[i].data = reinterpret_cast<const uint8_t *>(s->data());
      out[i].size = s->size();
    }
    new_tokens_.erase(new_tokens_.begin(), new_tokens_.begin() + n);
    return n;
  }

  /// How many distinct tokens have been interned so far.
  size_t size() const { return tokens_.size(); }
  /// Every token, for a caller that wants to dump the whole dictionary rather
  /// than stream the new ones.
  const std::unordered_set<std::string> &all() const { return tokens_; }

private:
  /// One comparison of the symbolic operand @p sym against the constant @p
  /// value, under predicate @p pred, at @p bits wide.  Routes it to whichever
  /// of the two channels it belongs to.
  void add_cmp(uint64_t value, dfsan_label sym, uint16_t pred, uint16_t bits) {
    // A byte compared for (in)equality against a byte-sized constant is a
    // character test, and characters are the thing that chains.  Widths above 8
    // reach here too because C promotes a char to int before comparing it; what
    // makes it a character test is the *source*, not the compare's width.
    if ((pred == __dfsan::bveq || pred == __dfsan::bvneq) && value < 256) {
      uint32_t input_id;
      uint64_t offset;
      if (single_byte_source(sym, &input_id, &offset)) {
        note_byte_cmp(input_id, offset, (uint8_t)value);
        return;
      }
    }
    // Only a plain byte image can be matched by putting bytes in the file.
    const size_t image = image_width(sym);
    if (image == 0) return;
    // The compare's width bounds the token from above -- the high bytes of a
    // 64-bit compare against a 4-byte image are the cast's zeroes, not the
    // file's -- and the image bounds it from below for the same reason.
    unsigned width = bits / 8;
    if (image < width) width = (unsigned)image;
    add_int(value, width);
  }

  /// Emit the run built so far, minus the scan loops inside it.
  ///
  /// `while (RAW != '?') NEXT;` compares one character against every offset it
  /// walks past, which is a run in exactly the sense above and means nothing as
  /// a file literal.  But a scan usually sits *between* two literals the parser
  /// did match -- "://" then a scan for '%' then '-' -- and those offsets are
  /// consecutive, so it all arrives as one run.  Cutting the scan out and
  /// keeping what is on either side is what recovers the "://".
  ///
  /// Three of the same byte in a row is the cut.  It catches nothing real: the
  /// syntax the byte chain is for repeats a character at most twice ("--",
  /// "]]", "[["), because a third would be ambiguous to the format's own reader.
  ///
  /// The cut is the only scan filter, which took a measurement to justify.  An
  /// earlier version instead rejected a whole segment when one byte held a
  /// majority of it, on the theory that a scan for a character *class* is mostly
  /// the same byte without ever repeating it three times running.  Instrumented
  /// over 1254 libxml2 seeds, that rule fired 0 times once the cut was in front
  /// of it -- and with the cut disabled it fired constantly, all of it on runs
  /// like "\t\t\t\t\t/" and "<\"\"\"\"\"" that the cut already handles.  The
  /// reason is structural: a run only grows while comparisons land on
  /// *consecutive* offsets one apiece, and a loop that compares two characters
  /// per position breaks the run at every position, so a scan that alternates
  /// never becomes a long run in the first place.
  void flush_run() {
    size_t seg = 0, i = 0;
    while (i < run_.size()) {
      size_t j = i + 1;
      while (j < run_.size() && run_[j] == run_[i]) ++j;
      if (j - i >= 3) {
        emit_run(seg, i);
        seg = j;
      }
      i = j;
    }
    emit_run(seg, run_.size());
    run_.clear();
    run_next_ = UINT64_MAX;
  }

  /// Intern run_[@p begin, @p end), what is left of the run between two cuts.
  void emit_run(size_t begin, size_t end) {
    if (end - begin < kMinTokenSize) return;
    add(run_.data() + begin, end - begin);
  }

  // True when every byte of @p n's low @p width bytes is the same.  Rules out
  // 0xffffffff, 0x00000000 and the 0xaaaa/0xcccc fill patterns, which occur
  // everywhere and mean nothing as a file literal.
  static bool uniform_bytes(uint64_t n, unsigned width) {
    const uint8_t b = (uint8_t)(n & 0xff);
    for (unsigned i = 1; i < width; ++i) {
      if ((uint8_t)((n >> (i * 8)) & 0xff) != b) return false;
    }
    return true;
  }

  /// The union table, walked directly.  The parser has its own copy but keeps
  /// get_label_info() protected, and the walk here deliberately does not go
  /// through the parser: a condition the parser refuses is exactly the one
  /// whose constants are worth handing to a mutator.
  dfsan_label_info *label_base_ = nullptr;
  size_t label_count_ = 0;
  size_t max_tokens_ = 4096;
  /// Interned so that the pointers take() hands out stay valid: an
  /// unordered_set never moves an element once inserted.
  std::unordered_set<std::string> tokens_;
  /// The ones interned since the last take().
  std::vector<const std::string *> new_tokens_;
  /// Condition labels already walked, cleared by end_input().
  std::unordered_set<dfsan_label> scanned_;

  /// The byte-comparison run being assembled, in trace order.  run_next_ is the
  /// offset the next comparison has to be at to continue it; UINT64_MAX when
  /// there is no run, which no real offset can equal.
  std::vector<uint8_t> run_;
  uint32_t run_input_ = 0;
  uint64_t run_next_ = UINT64_MAX;
};

} // namespace symsan
