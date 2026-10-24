#!/usr/bin/env python3
"""Turn an eval.py output dir into a record of what failed, where and why.

  tools/ucsan-kernel-eval/report.py <out dir>

Writes into <out dir>:
  failures.tsv   one row per (function, failure): module, function, stage, kind,
                 signature, workdir.  Sort/grep it for "which functions".
  REPORT.md      failures grouped by (stage, kind, signature): how many functions
                 and modules, example functions, an excerpt, and what is known
                 about the cause.  Meant to be read by whoever fixes them.

The cause text is written only where it was established; a group with no entry
in CAUSES says "not investigated" rather than guessing from its signature.
"""
import collections
import json
import os
import re
import sys

# what is known about a group: (stage, kind, signature prefix or "", text); first match wins.
# "CONFIRMED" = reproduced or read in code, ideally with a control; anything else says what
# was and was not checked.
CAUSES = [
    ("run", "memory-limit", "",
     "CONFIRMED runtime bug. memset/memcpy/memmove/_copy_from_user wrappers apply a symbolic "
     "length with no bound (real copy + 4x shadow), so the target touches GBs. See "
     "HANDOFF-ucsan-unbounded-memops.md."),
    ("instrument", "unsupported", "",
     "CONFIRMED UCSan gap. The entry function is variadic; the pass prints "
     "'VarArg entry points not supported' and emits a main() returning 1."),
    ("codegen", "duplicate-symbol", "",
     "CONFIRMED UCSanPass bug (control: llc on the original and on the normalized module is clean, "
     "UCSan alone reproduces it). The module declares a symbol `external global` but defines it in "
     "module-level asm (`.global optprobe_template_val`); UCSanPass rewrites undefined external globals "
     "as `weak global zeroinitializer` so the program links, which collides with the asm definition. "
     "Fix: skip globals whose symbol module asm defines (Module::CollectAsmSymbols)."),
    ("link", "hidden-undefined", "",
     "CONFIRMED UCSanPass bug, every function of kernel/exit.o. That file defines `__weak hidden void "
     "abort(void)`; the UCSan abilist has `abort=custom`, so the body is deleted and a hidden, undefined "
     "`abort` is left, which cannot bind to libc. Clearing `hidden` on that definition makes the "
     "build succeed (tested). Fix: reset visibility to default when a body is deleted for a custom/"
     "wrapped function (or in the harness normalization). Other kernel files define libc-named "
     "functions too (lib/string.o: strlen, strcmp, memcmp, ...) but did not fail."),
    ("link", "undefined-reference", "irq_",
     "CONFIRMED mechanism, UCSan gap. The reference is inside inline asm that UCSan does not lower "
     "(the kernel's call_on_irqstack: `movq %rsp,...; call irq_enter_rcu`, which also switches to the "
     "per-CPU IRQ stack). UCSan replaced the IR-level irq_enter_rcu with a stub, but the asm text still "
     "names the original symbol. Not-lowered asm is executed natively, so this would also misbehave "
     "at run time."),
    ("link", "undefined-reference", "__x86_return_thunk",
     "CONFIRMED harness artifact: the functions come from kernel module-level asm text (ASM_RET) that "
     "jumps to the return thunk, which the attribute normalization cannot reach. Fix in the harness "
     "(link a stub definition), not in UCSan."),
    ("link", "pie-relocation", "",
     "CONFIRMED harness artifact (reproduces on the plain module with no UCSan): kernel asm uses "
     "R_X86_64_32S absolute relocations, which cannot go into a PIE. Link with -no-pie in the harness."),
    ("instrument", "llvm-error", "",
     "CONFIRMED TaintPass bug (1 function, apply_relocation): 'Instruction does not dominate all uses'. "
     "UCSan alone verifies; UCSan+TaintPass with KO_TRACE_BB=1 KO_WRAP_INDIRECT_CALL=1 does not, with or "
     "without -taint-solve-ub."),
    ("run", "segv", "SIGSEGV in instrumented kernel code",
     "PARTLY ESTABLISHED, from a sample of 240 of these functions rebuilt and traced under strace "
     "(segv_census.tsv; tools/ucsan-kernel-eval/segv_census.py): 37.5% are general-protection faults "
     "(si_code SI_KERNEL) from PRIVILEGED INSTRUCTIONS executed natively in userspace: cli 33, wrmsr 14, "
     "rdmsr 13, sti 4, mov %cr0/%cr2/%cr3/%cr4 6, in/out 5, wbinvd 2, lgdt, lldt, xsetbv, debug-register "
     "moves. 55% are SEGV_MAPERR at NULL or below 4 GB on plain loads (half exactly NULL); consistent "
     "with per-CPU accesses (`add %gs:this_cpu_off`, which the lifter deliberately models as plain memory "
     "with gs base 0; the asm is present in the one function checked, not verified per fault). 7% showed no "
     "SIGSEGV on rerun. Direction for the first class: lower or no-op privileged instructions in the "
     "asm lifter instead of executing them."),
    ("run", "segv", "SIGSEGV in __taint_union_load",
     "The target faults inside the runtime's __taint_union_load (shadow read). Faulting address "
     "not captured. Not investigated further."),
    ("run", "hang", "",
     "A seed never returned within budget+grace. Not investigated (loop bound? blocked read?)."),
]


def cause(stage, kind, sig):
    for st, kd, prefix, text in CAUSES:
        if stage == st and kind == kd and sig.startswith(prefix):
            return text
    return "not investigated"


def fixup(rec):
    """Older records: a link failure misfiled as instrument (the classifier read the
    stage from a trimmed log).  Re-derive it from the excerpt."""
    ex = rec.get("excerpt", "")
    out = []
    for f in rec["failures"]:
        if f["stage"] == "instrument" and f["kind"] == "error" and "undefined reference to" in ex:
            syms = []
            for m in re.finditer(r"undefined reference to [`'\"]?([^'\"`\s]+)", ex):
                if m.group(1) not in syms:
                    syms.append(m.group(1))
            for s in syms or ["?"]:
                out.append({"stage": "link", "kind": "undefined-reference", "signature": s})
        elif (f["stage"] in ("instrument", "link") and "linker command failed" in f["signature"]
              and rec["module"] == "kernel/exit.o" and "R_X86_64_32S" not in ex):
            # every function of this module; one was rebuilt and the full log read
            out.append({"stage": "link", "kind": "hidden-undefined",
                        "signature": "hidden symbol `abort' isn't defined (module defines weak hidden abort)"})
        elif f["stage"] == "instrument" and "linker command failed" in f["signature"]:
            if "R_X86_64_32S" in ex:
                out.append({"stage": "link", "kind": "pie-relocation",
                            "signature": "R_X86_64_32S against .text in a PIE"})
            else:   # the excerpt was trimmed past the reason; do not guess it
                out.append({"stage": "link", "kind": "link-error", "signature": f["signature"]})
        elif f["stage"] == "instrument" and "already defined" in f["signature"]:
            m = re.search(r"symbol '([^']+)' is already defined", f["signature"])
            out.append({"stage": "codegen", "kind": "duplicate-symbol",
                        "signature": "symbol defined by module asm and by UCSan's weak stub" + (": " + m.group(1) if m else "")})
        else:
            out.append(f)
    return out


def main():
    out = os.path.abspath(sys.argv[1])
    rows = []
    groups = collections.defaultdict(lambda: {"fns": set(), "mods": set(), "ex": [], "excerpt": None, "wd": None})
    failed_fns = set()
    with open(os.path.join(out, "failures.jsonl")) as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            wd = r.get("workdir", "")
            wd = os.path.relpath(wd, out) if wd else ""
            failed_fns.add((r["module"], r["function"]))
            for x in fixup(r):
                key = (x["stage"], x["kind"], x["signature"])
                rows.append((r["module"], r["function"], x["stage"], x["kind"], x["signature"], wd))
                g = groups[key]
                g["fns"].add((r["module"], r["function"]))
                g["mods"].add(r["module"])
                if len(g["ex"]) < 4:
                    g["ex"].append((r["module"], r["function"], wd))
                if g["excerpt"] is None and r.get("excerpt"):
                    g["excerpt"] = r["excerpt"]

    total = 0
    findings = collections.Counter()
    with open(os.path.join(out, "results.tsv")) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) != 7:
                continue
            if p[2] == "skip":   # not evaluated (eval.py: variadic entry)
                continue
            total += 1
            if p[6] != "-":
                for kv in p[6].split(","):
                    k, v = kv.rsplit(":", 1)
                    findings[k] += int(v)

    rows.sort(key=lambda r: (r[2], r[3], r[4], r[0], r[1]))
    with open(os.path.join(out, "failures.tsv"), "w") as f:
        f.write("module\tfunction\tstage\tkind\tsignature\tworkdir\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    L = ["# UCSan kernel compatibility: what failed, where, why", ""]
    L.append("Partial run: %d functions evaluated of 57,661 (the run was stopped; enough cases). "
             "%d failed (%.1f%%)." % (total, len(failed_fns), 100.0 * len(failed_fns) / max(total, 1)))
    L.append("")
    L.append("Method: each function is its own UCSan scope (`ucsan_opt -b -i -t`), run under UcsanManager "
             "for 10 s (`tools/ucsan-kernel-eval/eval.py`). Modules were normalized first (kernel ABI "
             "attributes stripped) so they link as userspace; failures caused by that are labelled harness.")
    L.append("")
    L.append("Files: `failures.tsv` has every failing function (module, function, stage, kind, signature, "
             "workdir). Each workdir has `repro.sh`, `build.log`/`run/` and `scope.yaml`. "
             "`--retest <this dir>` reruns only these functions.")
    L.append("")
    L.append("Bug reports UCSan produced (findings, not failures): " +
             ", ".join("%s %d" % kv for kv in findings.most_common()))
    L.append("")
    L.append("## Failure groups")
    L.append("")
    L.append("| functions | modules | stage | kind | signature |")
    L.append("|---:|---:|---|---|---|")
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]["fns"]))
    # undefined-reference is one group per symbol; show the top ones, the rest are in the tsv
    for (stage, kind, sig), g in ordered[:60]:
        L.append("| %d | %d | %s | %s | `%s` |" % (len(g["fns"]), len(g["mods"]), stage, kind, sig.replace("|", "\\|")))
    if len(ordered) > 60:
        L.append("")
        L.append("(%d more groups, each smaller than %d functions, are in failures.tsv)" %
                 (len(ordered) - 60, len(ordered[59][1]["fns"]) + 1))
    L.append("")
    L.append("## Per group: examples, evidence, cause")
    for (stage, kind, sig), g in ordered[:40]:
        L.append("")
        L.append("### %s / %s / `%s`  (%d functions, %d modules)" % (stage, kind, sig, len(g["fns"]), len(g["mods"])))
        L.append("")
        L.append("Cause: " + cause(stage, kind, sig))
        L.append("")
        for m, fn, wd in g["ex"]:
            L.append("- `%s :: %s`  (`%s/repro.sh`)" % (m, fn, wd))
        if g["excerpt"]:
            ex = g["excerpt"].strip()[-500:]
            L.append("")
            L.append("```")
            L.append(ex)
            L.append("```")
    with open(os.path.join(out, "REPORT.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    print("wrote %s/{REPORT.md,failures.tsv}: %d failing functions, %d groups" % (out, len(failed_fns), len(groups)))


if __name__ == "__main__":
    main()
