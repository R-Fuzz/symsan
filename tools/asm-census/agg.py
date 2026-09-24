#!/usr/bin/env python3
# Summarize AsmCensus JSON lines (see README.md): counts per problem, by
# site, distinct (asm, constraint) template, and file.  Header inlines repeat
# across translation units, so the template count is the one to read for
# "how many distinct things need handling" and the site count for "how often
# does it run into it".
import collections as co
import json
import sys

R = [json.loads(l) for l in open(sys.argv[1])]
tmpl = lambda r: (r['asm'], r['cons'])

# Kinds of pointer operands UCSan passes through ucsan_check_pointer.
UNCHECKED = {'global', 'constexpr_global', 'constexpr_other', 'alloca',
             'function', 'null'}


def section(name, pred, key=None, top=8):
    S = [r for r in R if pred(r)]
    print(f"\n## {name}: {len(S)} sites, {len(set(map(tmpl, S)))} templates, "
          f"{len(set(r['file'] for r in S))} files")
    if key:
        c = co.Counter(k for r in S for k in key(r))
        for k, v in c.most_common(top):
            print(f"   {v:7d}  {k}")
    return S


def templates(S, top=8, width=80):
    c = co.Counter(r['asm'].replace('\n', ' | ')[:width] for r in S)
    for k, v in c.most_common(top):
        print(f"   {v:7d}  tmpl: {k!r}")


print(f"total sites {len(R)}, templates {len(set(map(tmpl, R)))}, "
      f"files {len(set(r['file'] for r in R))}, "
      f"functions {len(set((r['file'], r['fn']) for r in R))}")

S = section("memory output operand (shadow left stale)",
            lambda r: r['ind_out'], lambda r: r['ind_out'])
templates(S)
section("\"memory\" clobber without a memory output (opaque writes)",
        lambda r: r['mem_clobber'] and not r['ind_out'])
section("memory input operand", lambda r: r['ind_in'], lambda r: r['ind_in'])

section("pointer passed in a register",
        lambda r: r['reg_ptr_in'], lambda r: [p['kind'] for p in r['reg_ptr_in']])
S = section("pointer passed in a register and dereferenced by the template",
            lambda r: any(p['deref'] for p in r['reg_ptr_in']),
            lambda r: [p['kind'] for p in r['reg_ptr_in'] if p['deref']])
templates(S)

section("checked memory operand, check size != elementtype size",
        lambda r: r['size_bad'],
        lambda r: [f"{b['kind']} ucsan={b['ucsan']} elem={b['elem']}"
                   for b in r['size_bad']], 12)
S = section("  ... of which %gs: (percpu; benign while the harness's gs base is 0)",
            lambda r: r['size_bad'] and '%gs:' in r['asm'])

section("`call` detected", lambda r: 'call_action' in r,
        lambda r: [r['call_action']])
section("`call` -> asm deleted (symbol is not a module Function)",
        lambda r: r.get('call_action') == 'delete',
        lambda r: [f"{r['call_sym']} ret={r['ret']}"], 15)
section("`call` -> rewritten to a direct call",
        lambda r: r.get('call_action') == 'rewrite',
        lambda r: [f"{r['call_sym']} in={','.join(r['in_codes'])} ret={r['ret']}"], 15)
section("`call` -> left alone (operand/indirect target)",
        lambda r: r.get('call_action') == 'skip', lambda r: [r['call_sym']], 10)
section("`call` match preceded by a letter (e.g. syscall; false positive)",
        lambda r: r.get('call_prefix', '').isalpha(),
        lambda r: [r['call_prefix'] + 'call ' + r['call_sym']])
section("asm goto (callbr)", lambda r: r['callbr'])
section("asm goto with a `call` (the rewrite would drop a terminator)",
        lambda r: r['callbr'] and 'call_action' in r)

section("non-void result that is used (gets no label)",
        lambda r: r['ret_used'], lambda r: [r['ret']])

section("trap pattern", lambda r: r['trap'],
        lambda r: ['clobbers only -> exit(180)' if r['all_clobbers']
                   else 'has operands -> left in place (SIGILL)'])


def bug_kind(r):
    # _BUG_FLAGS operands: "i"(__FILE__), "i"(__LINE__), "i"(flags),
    # "i"(sizeof(struct bug_entry)); BUGFLAG_WARNING is bit 0.
    imm = r.get('imm', [])
    if len(imm) < 2:
        return 'unknown'
    return 'WARN (must continue)' if imm[-2] & 1 else 'BUG (must stop)'


S = section("kernel _BUG_FLAGS (ud2 + __bug_table)",
            lambda r: r['trap'] and '0x0f, 0x0b' in r['asm'] and not r['all_clobbers'],
            lambda r: [bug_kind(r)])

# The templates themselves, most common first: the view that matters for
# --instrumented runs (what inline asm is left, and whether it carries data).
c = co.Counter(r['asm'].replace('\n', ' | ')[:70] for r in R)
used = co.Counter(r['asm'].replace('\n', ' | ')[:70] for r in R if r['ret_used'])
mem = co.Counter(r['asm'].replace('\n', ' | ')[:70] for r in R if r['ind_out'])
print("\n## most common templates (sites, result used, writes memory)")
for k, v in c.most_common(25):
    print(f"   {v:7d} {used[k]:6d} {mem[k]:6d}  {k!r}")
