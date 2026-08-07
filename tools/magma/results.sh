#!/bin/bash
set -euo pipefail

##
# Summarize finished Magma campaigns.
#
#   tools/magma/results.sh                  # every campaign in the workdir
#   tools/magma/results.sh --target libpng --bugs
#
# Two independent records survive a campaign and they answer different
# questions, so both are printed:
#
#   $SHARED/monitor/<seconds>   Magma's own ground truth, one file per poll,
#                               a header of <BUG>_R,<BUG>_T and a row of
#                               cumulative counts.  _R is "the buggy code was
#                               reached", _T is "the canary fired".  This is
#                               the only thing here that measures *bugs*.
#   workdir/log/..._container.log  LibAFL's stats line, which carries exec/sec
#                               and the per-stage attribution (finds_symsan /
#                               finds_cmplog / finds_havoc) that says which
#                               stage earned the corpus.  Bug counts and stage
#                               attribution never appear in the same place.
#
# For the full survival analysis across repetitions, the magma checkout already
# has tools/benchd/exp2json.py (needs pandas); this is the quick read.
##

usage() {
    cat <<'EOF'
usage: tools/magma/results.sh [options]

  --fuzzer F     only this fuzzer   (default: all under workdir/ar)
  --target T     only this target
  --cid N        only this campaign id
  --bugs         per-bug time-to-reach / time-to-trigger, not just the counts
  --workdir D    (default: $MAGMA/workdir)

environment:
  MAGMA          magma checkout (default: /test/csong/magma-mr)
EOF
}

MAGMA="${MAGMA:-/test/csong/magma-mr}"
WORKDIR=""
F_FUZZER=""; F_TARGET=""; F_CID=""
SHOW_BUGS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --fuzzer)  F_FUZZER="$2"; shift 2 ;;
        --target)  F_TARGET="$2"; shift 2 ;;
        --cid)     F_CID="$2"; shift 2 ;;
        --bugs)    SHOW_BUGS=1; shift ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *)         echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

WORKDIR="${WORKDIR:-$MAGMA/workdir}"
test -d "$WORKDIR/ar" || { echo "no campaigns: $WORKDIR/ar" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Per column: the final cumulative count, and the first poll at which it went
# nonzero (the time-to-reach / time-to-trigger).
#
# awk opens the poll files itself rather than taking them as arguments.  A 24h
# campaign at POLL=5 leaves 17k of them, and passing that many paths on a
# command line is what makes xargs split the run into several awk processes --
# each with its own END block, so the aggregate would silently come out in
# pieces.  Emits "<column> <final> <first-nonzero|-1>" plus a __last row.
read_monitor() {
    local dir="$1" list="$TMP/polls"
    # Numeric names only: magma/run.sh writes each poll to $MONITOR/tmp first
    # and renames it, so a "tmp" can be there mid-campaign.
    find "$dir" -maxdepth 1 -type f -regextype posix-egrep -regex '.*/[0-9]+$' \
        > "$list"
    [ -s "$list" ] || return 1
    awk -v list="$list" '
        BEGIN {
            while ((getline f < list) > 0) {
                t = f; sub(/.*\//, "", t); t += 0
                if (t > last) last = t
                if ((getline hdr < f) <= 0) { close(f); continue }
                if ((getline row < f) <= 0) { close(f); continue }
                close(f)
                n = split(hdr, H, ","); split(row, V, ",")
                for (i = 1; i <= n; i++) {
                    k = H[i]; v = V[i] + 0
                    if (v > 0 && (!(k in first) || t < first[k])) first[k] = t
                    if (!(k in final_t) || t >= final_t[k]) {
                        final_t[k] = t; final[k] = v
                    }
                }
            }
            for (k in final)
                printf "%s %s %s\n", k, final[k], (k in first ? first[k] : -1)
            printf "__last %d 0\n", last
        }'
}

fmt_hms() {
    local s="$1"
    [ "$s" -lt 0 ] 2>/dev/null && { echo "-"; return; }
    printf '%dh%02dm%02ds' $((s/3600)) $((s%3600/60)) $((s%60))
}

found=0
for FUZZERDIR in "$WORKDIR"/ar/*; do
    [ -d "$FUZZERDIR" ] || continue
    FUZZER="$(basename "$FUZZERDIR")"
    [ -z "$F_FUZZER" ] || [ "$F_FUZZER" = "$FUZZER" ] || continue

    for TARGETDIR in "$FUZZERDIR"/*; do
        [ -d "$TARGETDIR" ] || continue
        TARGET="$(basename "$TARGETDIR")"
        [ -z "$F_TARGET" ] || [ "$F_TARGET" = "$TARGET" ] || continue

        for PROGRAMDIR in "$TARGETDIR"/*; do
            [ -d "$PROGRAMDIR" ] || continue
            PROGRAM="$(basename "$PROGRAMDIR")"

            for CAMPAIGNDIR in $(ls -1v "$PROGRAMDIR" 2>/dev/null); do
                CID="$CAMPAIGNDIR"
                CAMPAIGNDIR="$PROGRAMDIR/$CID"
                [ -d "$CAMPAIGNDIR" ] || continue
                [ -z "$F_CID" ] || [ "$F_CID" = "$CID" ] || continue
                found=1

                echo "============================================================"
                echo "$FUZZER / $TARGET / $PROGRAM / $CID"

                # Either a tarball (the default) or a plain directory
                # (NO_ARCHIVE=1).  Only the monitor dir is unpacked; the corpus
                # is what extract-corpus.sh is for.
                SRC="$TMP/$FUZZER-$TARGET-$PROGRAM-$CID"
                mkdir -p "$SRC"
                BALL="$CAMPAIGNDIR/ball.tar"
                if [ -f "$BALL" ]; then
                    echo "  archive   $BALL ($(du -h "$BALL" | cut -f1))"
                    tar -C "$SRC" -xf "$BALL" ./monitor 2>/dev/null || true
                    nq=$(tar tf "$BALL" | grep -c '^\./findings/queue/[^.]' || true)
                    nc=$(tar tf "$BALL" | grep -c '^\./findings/crashes/[^.]' || true)
                else
                    echo "  dir       $CAMPAIGNDIR"
                    [ -d "$CAMPAIGNDIR/monitor" ] && cp -r "$CAMPAIGNDIR/monitor" "$SRC/"
                    nq=$( (find "$CAMPAIGNDIR/findings/queue" -type f ! -name '.*' 2>/dev/null || true) | wc -l)
                    nc=$( (find "$CAMPAIGNDIR/findings/crashes" -type f ! -name '.*' 2>/dev/null || true) | wc -l)
                fi
                echo "  corpus    $nq entries, $nc crash inputs"

                if [ -d "$SRC/monitor" ] && M="$(read_monitor "$SRC/monitor")"; then
                    last="$(awk '$1=="__last"{print $2}' <<<"$M")"
                    reached=$(awk '$1 ~ /_R$/ && $2 > 0' <<<"$M" | wc -l)
                    nbugs=$(awk '$1 ~ /_R$/' <<<"$M" | wc -l)
                    trig=$(awk '$1 ~ /_T$/ && $2 > 0' <<<"$M" | wc -l)
                    echo "  duration  $(fmt_hms "$last") (last poll)"
                    echo "  bugs      reached $reached/$nbugs, triggered $trig/$nbugs"
                    if [ "$SHOW_BUGS" = 1 ]; then
                        printf '            %-10s %10s %12s %10s %12s\n' \
                               BUG hits TTR hits TTE
                        awk '$1 ~ /_R$/ {sub(/_R$/,"",$1); r[$1]=$2; rt[$1]=$3}
                             $1 ~ /_T$/ {sub(/_T$/,"",$1); t[$1]=$2; tt[$1]=$3}
                             END {for (b in r) printf "%s %s %s %s %s\n",
                                  b, r[b], rt[b], t[b]+0, (b in tt ? tt[b] : -1)}' \
                            <<<"$M" | sort | while read -r b rh rt th tt; do
                            printf '            %-10s %10s %12s %10s %12s\n' \
                                   "$b" "$rh" "$(fmt_hms "$rt")" "$th" "$(fmt_hms "$tt")"
                        done
                    fi
                else
                    echo "  bugs      (no monitor data)"
                fi

                CLOG="$WORKDIR/log/${FUZZER}_${TARGET}_${PROGRAM}_${CID}_container.log"
                if [ -r "$CLOG" ]; then
                    stats="$(grep 'run time:' "$CLOG" | tail -1 || true)"
                    if [ -n "$stats" ]; then
                        # One field per line: the stats line is ~250 characters
                        # and the interesting parts are at both ends of it.
                        echo "  fuzzer    ${stats#*] }" | fold -s -w 76 \
                            | sed '2,$s/^/            /'
                    fi
                    # Two decline sites, and which one fires is the interesting
                    # part -- so they are counted apart rather than summed.  A
                    # parse decline (rgd-parser.cpp:879) drops the clause before
                    # any solver sees it; a JIT decline (jigsaw jit.cc:883) means
                    # the task was built and reached the ladder, and only jigsaw
                    # bowed out, so z3 still had its turn.  Moving a count from
                    # the first line to the second is progress, and a tool that
                    # added them would report it as no change.
                    #
                    # Only the *causes* are counted: each has a paired follow-on
                    # ("failed to construct task for clause", "failed to add
                    # function") that would otherwise double every figure.
                    perr="$(grep -cE '^invalid op' "$CLOG" || true)"
                    jerr="$(grep -cE '^Invalid node' "$CLOG" || true)"
                    if [ "${perr:-0}" -gt 0 ]; then
                        echo "  parse     $perr clauses dropped by rgd-parser:" \
                             "$(grep -hoE '^invalid op: [0-9]+' "$CLOG" \
                                | sort | uniq -c | sort -rn \
                                | awk '{printf "op %s x%s  ", $4, $1}' || true)"
                    fi
                    if [ "${jerr:-0}" -gt 0 ]; then
                        echo "  jit       $jerr tasks declined by jigsaw codegen" \
                             "(built and tried; z3 still got them)"
                    fi
                else
                    echo "  fuzzer    (no container log at $CLOG)"
                fi
            done
        done
    done
done

[ "$found" = 1 ] || echo "no campaigns matched."
