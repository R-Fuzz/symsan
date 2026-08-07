#!/bin/bash
set -euo pipefail

##
# Recover the test cases a Magma campaign produced.
#
#   tools/magma/extract-corpus.sh --target libpng /tmp/libpng-corpus
#   tools/magma/extract-corpus.sh --what crashes --cid 6 /tmp/libpng-crashes
#
# The corpus is not lost when a campaign ends: captain tars $SHARED into
# workdir/ar/<fuzzer>/<target>/<program>/<cid>/ball.tar, and the LibAFL
# OnDiskCorpus is in there under findings/queue.  That is where the seed corpus
# for a parse sweep or a solver A/B comes from -- a corpus a real campaign
# reached is worth more than a hand-picked one, and re-running the campaign to
# get it back costs the campaign.
#
# Only the payload files are copied.  OnDiskCorpus writes two dotfile sidecars
# next to every entry (`.<name>` and `.<name>_1.metadata`); they are LibAFL's
# bookkeeping, not inputs, and feeding them to a target as seeds is how a sweep
# ends up with twice the entries and a pile of parse failures that mean nothing.
##

usage() {
    cat <<'EOF'
usage: tools/magma/extract-corpus.sh [options] <dest-dir>
       tools/magma/extract-corpus.sh --list

  --fuzzer F     (default: libafl_symsan)
  --target T     (default: the only target present, else required)
  --program P    (default: the only program present, else required)
  --cid N        campaign id (default: the highest one that has results)
  --what W       queue | crashes | both      (default: queue)
  --list         list the campaigns available, and exit
  --workdir D    (default: $MAGMA/workdir)

environment:
  MAGMA          magma checkout (default: /test/csong/magma-mr)
EOF
}

MAGMA="${MAGMA:-/test/csong/magma-mr}"
WORKDIR=""
FUZZER=libafl_symsan
TARGET=""; PROGRAM=""; CID=""
WHAT=queue
LIST=0
DEST=""

while [ $# -gt 0 ]; do
    case "$1" in
        --fuzzer)  FUZZER="$2"; shift 2 ;;
        --target)  TARGET="$2"; shift 2 ;;
        --program) PROGRAM="$2"; shift 2 ;;
        --cid)     CID="$2"; shift 2 ;;
        --what)    WHAT="$2"; shift 2 ;;
        --list)    LIST=1; shift ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*)        echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)         DEST="$1"; shift ;;
    esac
done

WORKDIR="${WORKDIR:-$MAGMA/workdir}"
AR="$WORKDIR/ar"
test -d "$AR" || { echo "no campaigns: $AR" >&2; exit 1; }

case "$WHAT" in queue|crashes|both) ;; *) echo "--what: $WHAT" >&2; exit 2 ;; esac

if [ "$LIST" = 1 ]; then
    for d in "$AR"/*/*/*/*; do
        [ -d "$d" ] || continue
        rel="${d#"$AR"/}"
        if [ -f "$d/ball.tar" ]; then
            nq=$(tar tf "$d/ball.tar" | grep -c '^\./findings/queue/[^.]' || true)
            nc=$(tar tf "$d/ball.tar" | grep -c '^\./findings/crashes/[^.]' || true)
        else
            nq=$( (find "$d/findings/queue" -type f ! -name '.*' 2>/dev/null || true) | wc -l)
            nc=$( (find "$d/findings/crashes" -type f ! -name '.*' 2>/dev/null || true) | wc -l)
        fi
        printf '%-56s queue=%-6s crashes=%s\n' "$rel" "$nq" "$nc"
    done
    exit 0
fi

[ -n "$DEST" ] || { usage >&2; exit 2; }

pick_one() {
    ##
    # $1: description, $2: parent dir.  Echoes the single child, or fails with
    # the list -- guessing which of several targets was meant is exactly the
    # kind of silent wrong answer this whole exercise is trying to avoid.
    local what="$1" parent="$2"
    local kids=(); local k
    for k in "$parent"/*; do [ -e "$k" ] && kids+=("$(basename "$k")"); done
    if [ ${#kids[@]} -eq 1 ]; then echo "${kids[0]}"; return 0; fi
    echo "several $what under $parent: ${kids[*]:-(none)} -- name one" >&2
    return 1
}

test -d "$AR/$FUZZER" || { echo "no such fuzzer in $AR: $FUZZER" >&2; exit 1; }
[ -n "$TARGET" ]  || TARGET="$(pick_one targets "$AR/$FUZZER")"
[ -n "$PROGRAM" ] || PROGRAM="$(pick_one programs "$AR/$FUZZER/$TARGET")"

BASE="$AR/$FUZZER/$TARGET/$PROGRAM"
test -d "$BASE" || { echo "no such campaign path: $BASE" >&2; exit 1; }
if [ -z "$CID" ]; then
    # Highest cid that actually has results.  get_next_cid() in captain's run.sh
    # mkdirs the campaign directory before the campaign starts, so an empty one
    # is a campaign that never produced anything (or is running right now).
    for c in $(ls -1v "$BASE" | tac); do
        if [ -f "$BASE/$c/ball.tar" ] || [ -d "$BASE/$c/findings" ]; then
            CID="$c"; break
        fi
    done
    [ -n "$CID" ] || { echo "no campaign with results under $BASE" >&2; exit 1; }
fi

CAMPAIGN="$BASE/$CID"
echo "== $FUZZER / $TARGET / $PROGRAM / $CID"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$DEST"
total=0
for w in queue crashes; do
    [ "$WHAT" = both ] || [ "$WHAT" = "$w" ] || continue

    src=""
    if [ -f "$CAMPAIGN/ball.tar" ]; then
        tar -C "$TMP" -xf "$CAMPAIGN/ball.tar" "./findings/$w" 2>/dev/null || true
        src="$TMP/findings/$w"
    elif [ -d "$CAMPAIGN/findings/$w" ]; then
        src="$CAMPAIGN/findings/$w"
    fi
    if [ -z "$src" ] || [ ! -d "$src" ]; then
        echo "   $w: (none)"
        continue
    fi

    out="$DEST"
    [ "$WHAT" = both ] && { out="$DEST/$w"; mkdir -p "$out"; }

    # One batched cp rather than a loop: 811 entries is a normal libpng queue
    # and a fork per file is the slowest part of the script.
    n=$(find "$src" -type f ! -name '.*' -printf . | wc -c)
    if [ "$n" -gt 0 ]; then
        find "$src" -type f ! -name '.*' -exec cp -t "$out" {} +
    fi
    echo "   $w: $n files -> $out"
    total=$((total + n))
done

echo "== $total files."
