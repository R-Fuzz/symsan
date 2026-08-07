#!/bin/bash
set -euo pipefail

##
# Run a Magma campaign for the coverage-guided SymSan fuzzer (libafl_symsan),
# from *this* working tree, in one command.
#
#   tools/magma/campaign.sh --timeout 24h --repeat 3 libpng
#
# The Magma checkout is a separate tree ($MAGMA below) and the fuzzer directory
# in it -- fuzzers/libafl_symsan -- is untracked there, so this script lives
# here instead: this is the repo that actually changes between campaigns, and
# the one whose history explains a difference in the numbers.
#
# What it does that `./tools/captain/run.sh <rc>` on its own does not:
#
#   1. Snapshots this working tree into the image (sync-src.sh) and *deletes
#      the old image first*.  captain's run.sh skips the build when an image of
#      the same name exists, so without the rmi a campaign silently measures
#      whatever was built last week.  That is the single most expensive mistake
#      available here, because nothing in the output says which build ran.
#   2. Records what went into the image, and refuses --no-rebuild when the
#      request no longer matches it.
#   3. Writes the rc file, so the arm, the timeout and the per-fuzzer-AND-target
#      FUZZARGS name are derived rather than remembered.
#   4. Refuses to start while another campaign is running.  captain mounts a
#      tmpfs over $WORKDIR/cache on entry and umounts it on exit, so a second
#      run.sh pulls the filesystem out from under the first one's live
#      campaigns.
##

usage() {
    cat <<'EOF'
usage: tools/magma/campaign.sh [options] <target>...

  <target>          a directory under $MAGMA/targets: libpng libxml2 libtiff
                    libsndfile lua openssl php poppler sqlite3

options:
  --arm ARM         both | symsan | cmplog | havoc   (default: both)
                      both    symsan + cmplog stages, the headline arm
                      symsan  concolic only; USE_CMPLOG=0, needs its own build
                      cmplog  cmplog only; --symsan-no-i2s --symsan-no-jigsaw,
                              i.e. SymSan still traces but solves nothing.
                              Shares the `both` build.
                      havoc   neither stage; USE_SYMSAN=0 USE_CMPLOG=0, own
                              build, branch map forced off.  This is a *LibAFL*
                              floor, not stock AFL++ -- it holds the scheduler,
                              mutators, map and harness fixed and varies only
                              the stage, so it answers "does the concolic stage
                              earn its keep here", not "do we beat AFL++".
  --timeout T       wall clock per campaign, magma syntax (default: 10m)
                      10m answers "does the pipeline still work end to end".
                      24h is the only number a bug-finding claim can rest on.
  --repeat N        campaigns per program (default: 1; use >= 3 to compare arms)
  --program P       run only program P of the target; repeatable, and needs a
                    single target so there is no question which one it names.
                    This selects which *campaigns are scheduled*, not what the
                    image contains: targets/<t>/build.sh builds all of its
                    programs either way, and instrument.sh instruments all of
                    them (it reads configrc, not this).  Use it to spend cores
                    on the program you care about.
  --branch-map 0|1  build the coverage/concolic edge-id join (default: 1).
                    Fine on multi-program targets -- each program is a separate
                    link and gets its own .bmap.  Only AFL_LLVM_DOCUMENT_IDS is
                    ambiguous there, and that file is covcheck's ground truth
                    rather than an input to the join.
  --solve-ub        add --symsan-solve-ub
  --fuzzargs "..."  extra symsan-fuzz arguments, appended after the arm's own
  --build-line "L"  append a raw bash line to src/instrumentrc; repeatable.
                    instrument.sh sources that file inside the image before it
                    reads CFLAGS, so this is the channel for build flags captain
                    has no --build-arg for.  It joins the image stamp, so
                    --no-rebuild still refuses to measure the wrong build.
                    e.g. --build-line 'CFLAGS="${CFLAGS/-O0/-O2}"'
  --workers N       size of the CPU pool (default: repeat x programs, so every
                    scheduled campaign gets its own pinned core and none wait;
                    several targets build more than one program)
  --no-rebuild      reuse the existing image; verified against its stamp
  --force           with --no-rebuild, proceed despite a stamp mismatch
  --cache-on-disk   skip the tmpfs mount (no sudo, slower canary handling)
  --dry-run         print the rc file and the commands; run nothing
  --symsan PATH     symsan checkout to ship (default: this repo)
  --branch B        symsan branch to ship (default: libafl)

environment:
  MAGMA             magma checkout (default: /test/csong/magma-mr)
EOF
}

MAGMA="${MAGMA:-/test/csong/magma-mr}"
SYMSAN="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRANCH=libafl
FUZZER=libafl_symsan

ARM=both
TIMEOUT=10m
REPEAT=1
SELECT_PROGRAMS=()
BRANCH_MAP=1
BRANCH_MAP_SET=0
SOLVE_UB=0
EXTRA_FUZZARGS=""
BUILD_LINES=()
WORKERS=""
REBUILD=1
FORCE=0
CACHE_ON_DISK=0
DRY_RUN=0
TARGETS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --arm)          ARM="$2"; shift 2 ;;
        --timeout)      TIMEOUT="$2"; shift 2 ;;
        --repeat)       REPEAT="$2"; shift 2 ;;
        --program)      SELECT_PROGRAMS+=("$2"); shift 2 ;;
        --branch-map)   BRANCH_MAP="$2"; BRANCH_MAP_SET=1; shift 2 ;;
        --solve-ub)     SOLVE_UB=1; shift ;;
        --fuzzargs)     EXTRA_FUZZARGS="$2"; shift 2 ;;
        --build-line)   BUILD_LINES+=("$2"); shift 2 ;;
        --workers)      WORKERS="$2"; shift 2 ;;
        --no-rebuild)   REBUILD=0; shift ;;
        --force)        FORCE=1; shift ;;
        --cache-on-disk) CACHE_ON_DISK=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        --symsan)       SYMSAN="$2"; shift 2 ;;
        --branch)       BRANCH="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        -*)             echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)              TARGETS+=("$1"); shift ;;
    esac
done

[ ${#TARGETS[@]} -gt 0 ] || { usage >&2; exit 2; }
test -d "$MAGMA/tools/captain" || {
    echo "not a magma checkout: $MAGMA (set \$MAGMA)" >&2; exit 1; }
test -d "$MAGMA/fuzzers/$FUZZER" || {
    echo "$MAGMA/fuzzers/$FUZZER is missing -- this tree is untracked in the" \
         "magma repo, so it can be lost by a checkout there" >&2; exit 1; }

for t in "${TARGETS[@]}"; do
    test -d "$MAGMA/targets/$t" || { echo "no such target: $t" >&2; exit 1; }
done

case "$ARM" in
    both|symsan|cmplog|havoc) ;;
    *)  echo "unknown arm: $ARM" >&2; exit 2 ;;
esac

# --program restricts the schedule to a subset of the target's configrc
# PROGRAMS.  Checked against that list here rather than left to captain: an
# unknown name would otherwise reach get_var_or_default, come back as a program
# that is not in $OUT, and fail inside the container ten minutes later.
if [ ${#SELECT_PROGRAMS[@]} -gt 0 ]; then
    if [ ${#TARGETS[@]} -ne 1 ]; then
        echo "--program names a program of one target, but ${#TARGETS[@]} were" \
             "given (${TARGETS[*]}); run them separately." >&2
        exit 2
    fi
    # shellcheck disable=SC1090
    PROGRAMS=(); source "$MAGMA/targets/${TARGETS[0]}/configrc"
    for p in "${SELECT_PROGRAMS[@]}"; do
        contains=0
        for q in "${PROGRAMS[@]}"; do [ "$p" = "$q" ] && contains=1; done
        [ "$contains" = 1 ] || {
            echo "${TARGETS[0]} has no program '$p'; it builds ${PROGRAMS[*]}" >&2
            exit 1; }
    done
fi

# The havoc floor is a coverage build and nothing else, so it turns the branch
# map off rather than making the caller remember to -- the map's only consumer
# is the concolic stage this arm does not build, and instrument.sh refuses the
# combination outright.  An explicit --branch-map 1 is still an error: it says
# the caller believes something about this arm that is not true.
if [ "$ARM" = havoc ]; then
    if [ "$BRANCH_MAP_SET" = 1 ] && [ "$BRANCH_MAP" = 1 ]; then
        echo "--arm havoc builds no concolic target, so there is nothing for" \
             "--branch-map 1 to feed." >&2
        exit 2
    fi
    if [ "$SOLVE_UB" = 1 ]; then
        echo "--arm havoc runs no concolic stage, so --solve-ub would be" \
             "accepted by the fuzzer and do nothing." >&2
        exit 2
    fi
    BRANCH_MAP=0
fi

# USE_BRANCH_MAP used to be refused here when the target builds more than one
# program, on the grounds that AFL++'s LTO pass numbers edges per link and one
# document-ids file then describes neither binary.  Half of that is true and it
# is the harmless half: lld writes one merged module per link, so every program
# gets its own precodegen .bc, its own edge ids and its own .bmap, and the
# backend only ever holds one at a time.  What genuinely cannot be attributed is
# AFL_LLVM_DOCUMENT_IDS -- one file per build, appended to per link -- and that
# file is covcheck's ground truth, not an input to the join.  So instrument.sh
# now warns instead of refusing, and so does this.
if [ "$BRANCH_MAP" = 1 ]; then
    for t in "${TARGETS[@]}"; do
        # shellcheck disable=SC1090
        PROGRAMS=(); source "$MAGMA/targets/$t/configrc"
        if [ ${#PROGRAMS[@]} -ne 1 ]; then
            echo "note: $t builds ${#PROGRAMS[@]} programs (${PROGRAMS[*]});" \
                 "each gets its own .bmap, but the document-ids file is their" \
                 "union so covcheck cannot use it." >&2
        fi
    done
fi

# ---------------------------------------------------------------------------
# One campaign runner at a time.
#
# Not a nicety.  run.sh mounts a tmpfs over $WORKDIR/cache when it starts and
# umounts it in its EXIT trap; the second instance's umount destroys the first
# instance's live campaign directories, and the first instance goes on writing
# into a directory that no longer backs anything.
#
# Our own process tree is excluded from the scan: pgrep -f matches on the whole
# command line, and the shell that invoked this script may well have the string
# "tools/captain/run.sh" in its own argv (a wrapper, a heredoc, an editor
# command).  Matching that and refusing to run is a false alarm that looks
# exactly like the real one.
#
# `|| true` on both pipelines: pgrep exits 1 when nothing matches, which under
# `set -e -o pipefail` would abort the script -- silently, since the failing
# command is a command substitution in an assignment and prints nothing.
ancestors=" "
p=$$
while [ "${p:-0}" -gt 1 ]; do
    ancestors="$ancestors$p "
    p="$( (ps -o ppid= -p "$p" 2>/dev/null || true) | tr -d ' ')"
done
others="$( (pgrep -af 'tools/captain/run\.sh' 2>/dev/null || true) \
          | awk -v skip="$ancestors" '{ if (index(skip, " " $1 " ") == 0) print }')"
if [ -n "$others" ]; then
    echo "a captain run.sh is already running:" >&2
    echo "$others" >&2
    echo "refusing to start a second one -- they share the tmpfs on" \
         "$MAGMA/workdir/cache." >&2
    exit 1
fi
if mountpoint -q -- "$MAGMA/workdir/cache" 2>/dev/null; then
    echo "$MAGMA/workdir/cache is still a mountpoint: either a campaign is" \
         "running, or one died without umounting.  Check, then" \
         "\`sudo umount $MAGMA/workdir/cache\`." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build-time configuration.  instrument.sh sources src/instrumentrc inside the
# container; captain forwards only a fixed list of --build-args, so this file
# is the only channel for anything else.
INSTRUMENTRC="$MAGMA/fuzzers/$FUZZER/src/instrumentrc"
instrumentrc_body() {
    echo "# generated by symsan tools/magma/campaign.sh -- edits are overwritten"
    [ "$BRANCH_MAP" = 1 ] && echo "USE_BRANCH_MAP=1"
    [ "$ARM" = symsan ]   && echo "USE_CMPLOG=0"
    # Both off for havoc.  USE_SYMSAN=0 also plants $OUT/no_symsan, which is
    # what lets run.sh tell "this arm has no concolic stage" apart from "the
    # concolic build failed" -- it refuses to start on the latter.
    [ "$ARM" = havoc ]    && { echo "USE_CMPLOG=0"; echo "USE_SYMSAN=0"; }
    # --build-line, verbatim and last, so it can override anything above and
    # rewrite the CFLAGS the Dockerfile baked in.
    local l
    for l in ${BUILD_LINES+"${BUILD_LINES[@]}"}; do echo "$l"; done
    return 0
}

# Fingerprint of the source that goes into the image.  sync-src.sh ships the
# working tree (via `git stash create`) when it is dirty and the branch tip
# otherwise, and neither includes untracked files -- so HEAD plus the diff
# against it is exactly what lands in the tarball.
symsan_fingerprint() {
    local head diff
    head="$(git -C "$SYMSAN" rev-parse HEAD)"
    diff="$(git -C "$SYMSAN" diff HEAD -- | sha256sum | cut -c1-16)"
    echo "$head+$diff"
}

stamp_path() { echo "$MAGMA/fuzzers/$FUZZER/src/.image-stamp-$1"; }

# ---------------------------------------------------------------------------
FINGERPRINT="$(symsan_fingerprint)"
# `|| true`: with every build option off, instrumentrc_body emits only its
# comment line, grep matches nothing and exits 1 -- which pipefail would turn
# into a silent abort.
WANT_RC="$( (instrumentrc_body | grep -v '^#' || true) | sort | tr '\n' ' ')"

echo "== symsan   $SYMSAN @ $(git -C "$SYMSAN" rev-parse --short HEAD)$(git -C "$SYMSAN" diff --quiet HEAD -- || echo ' +uncommitted')"
echo "== magma    $MAGMA"
echo "== arm      $ARM   branch-map=$BRANCH_MAP solve-ub=$SOLVE_UB"
echo "== schedule ${TARGETS[*]}${SELECT_PROGRAMS+" (${SELECT_PROGRAMS[*]} only)"}  timeout=$TIMEOUT repeat=$REPEAT"
echo "== build    ${WANT_RC:-(defaults)}"

if [ "$REBUILD" = 1 ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "-- would write $INSTRUMENTRC:"; instrumentrc_body | sed 's/^/     /'
        echo "-- would run $MAGMA/fuzzers/$FUZZER/sync-src.sh $SYMSAN $BRANCH"
        for t in "${TARGETS[@]}"; do
            echo "-- would docker rmi -f magma/$FUZZER/$t"
            echo "-- would run FUZZER=$FUZZER TARGET=$t $MAGMA/tools/captain/build.sh"
        done
    else
        instrumentrc_body > "$INSTRUMENTRC"
        "$MAGMA/fuzzers/$FUZZER/sync-src.sh" "$SYMSAN" "$BRANCH"

        for t in "${TARGETS[@]}"; do
            # The rmi is the point of this script.  captain's run.sh does
            # `docker image inspect || build`, so an image that exists is an
            # image that is used, however old the code in it is.
            docker rmi -f "magma/$FUZZER/$t" >/dev/null 2>&1 || true
            echo "== building magma/$FUZZER/$t (log:" \
                 "$MAGMA/workdir/log/${FUZZER}_${t}_build.log)"
            mkdir -p "$MAGMA/workdir/log"
            if ! (cd "$MAGMA" && FUZZER="$FUZZER" TARGET="$t" \
                    ./tools/captain/build.sh) \
                    > "$MAGMA/workdir/log/${FUZZER}_${t}_build.log" 2>&1; then
                echo "build failed; tail of the log:" >&2
                tail -40 "$MAGMA/workdir/log/${FUZZER}_${t}_build.log" >&2
                exit 1
            fi
            {
                echo "target=$t"
                echo "built=$(date -Is)"
                echo "symsan=$FINGERPRINT"
                echo "branch=$BRANCH"
                echo "instrumentrc=$WANT_RC"
            } > "$(stamp_path "$t")"
        done
    fi
else
    # Reusing an image is fine -- the cmplog arm is deliberately the same build
    # as `both` -- but only if it is the build being asked for.
    for t in "${TARGETS[@]}"; do
        docker image inspect "magma/$FUZZER/$t" >/dev/null 2>&1 || {
            echo "--no-rebuild, but there is no magma/$FUZZER/$t image" >&2
            exit 1; }
        s="$(stamp_path "$t")"
        if [ ! -r "$s" ]; then
            echo "warning: magma/$FUZZER/$t has no stamp -- it was not built" \
                 "by this script, so what is in it is unknown." >&2
            [ "$FORCE" = 1 ] || { echo "pass --force to use it anyway." >&2; exit 1; }
            continue
        fi
        echo "-- reusing magma/$FUZZER/$t:"; sed 's/^/     /' "$s"
        got_rc="$(sed -n 's/^instrumentrc=//p' "$s")"
        got_fp="$(sed -n 's/^symsan=//p' "$s")"
        bad=0
        [ "$got_rc" = "$WANT_RC" ] || {
            echo "   ! build config differs: image has '${got_rc:-(defaults)}'," \
                 "you asked for '${WANT_RC:-(defaults)}'" >&2; bad=1; }
        [ "$got_fp" = "$FINGERPRINT" ] || {
            echo "   ! source differs: image has $got_fp, tree is $FINGERPRINT" >&2
            bad=1; }
        if [ "$bad" = 1 ] && [ "$FORCE" != 1 ]; then
            echo "drop --no-rebuild, or pass --force to measure the old build" \
                 "on purpose." >&2
            exit 1
        fi
    done
fi

# ---------------------------------------------------------------------------
# Run-time configuration: the rc file captain sources.
FUZZARGS=""
[ "$ARM" = cmplog ] && FUZZARGS="--symsan-no-i2s --symsan-no-jigsaw"
[ "$SOLVE_UB" = 1 ] && FUZZARGS="$FUZZARGS --symsan-solve-ub"
[ -n "$EXTRA_FUZZARGS" ] && FUZZARGS="$FUZZARGS $EXTRA_FUZZARGS"
FUZZARGS="$(echo "$FUZZARGS" | xargs || true)"

# captain schedules one campaign per (fuzzer, target, *program*) per repetition,
# so the pool has to be sized in programs, not targets -- libxml2, libtiff,
# poppler, openssl and php each build several.  Undersize it and the extra
# campaigns simply queue, which is correct but turns a 24h schedule into 48h
# without saying so.
nprograms=0
for t in "${TARGETS[@]}"; do
    # shellcheck disable=SC1090
    PROGRAMS=(); source "$MAGMA/targets/$t/configrc"
    if [ ${#SELECT_PROGRAMS[@]} -gt 0 ]; then
        nprograms=$(( nprograms + ${#SELECT_PROGRAMS[@]} ))
    else
        nprograms=$(( nprograms + ${#PROGRAMS[@]} ))
    fi
done
: "${WORKERS:=$(( REPEAT * nprograms ))}"

# Under --dry-run this goes to a scratch file: printing what would be written
# is the whole point, and leaving a real one behind would make the next
# hand-run of captain pick up a config nobody asked it to use.
RC_NAME="campaign.generated.rc"
RC="$MAGMA/tools/captain/$RC_NAME"
[ "$DRY_RUN" = 1 ] && RC="$(mktemp -t campaign.generated.XXXX.rc)"
{
    echo "# Generated by symsan tools/magma/campaign.sh -- do not hand-edit."
    echo "# arm=$ARM  symsan=$FINGERPRINT  build='${WANT_RC:-defaults}'"
    echo "WORKDIR=./workdir"
    echo "REPEAT=$REPEAT"
    echo "TIMEOUT=$TIMEOUT"
    echo "POLL=5"
    [ "$CACHE_ON_DISK" = 1 ] && echo "CACHE_ON_DISK=1"
    # One core per campaign, and exactly as many cores as campaigns, so nothing
    # queues behind a busy pool and nothing shares a core with another arm.
    echo "WORKERS=$WORKERS"
    echo "FUZZERS=($FUZZER)"
    echo "${FUZZER}_TARGETS=(${TARGETS[*]})"
    # run.sh:291 does get_var_or_default $FUZZER $TARGET PROGRAMS, so this
    # overrides the DEFAULT_<target>_PROGRAMS that common.sh derived from
    # configrc -- and, like FUZZARGS, the name has to carry both the fuzzer and
    # the target or nothing reads it.
    if [ ${#SELECT_PROGRAMS[@]} -gt 0 ]; then
        echo "${FUZZER}_${TARGETS[0]}_PROGRAMS=(${SELECT_PROGRAMS[*]})"
    fi
    # SymSan's launcher keeps its configuration in a C file-global, so a second
    # concolic stage in the same process is refused (Error::Busy).  Raising this
    # needs LibAFL's Launcher, which forks a process per worker.
    echo "${FUZZER}_CAMPAIGN_WORKERS=1"
    if [ -n "$FUZZARGS" ]; then
        # get_var_or_default() looks FUZZARGS up per fuzzer AND target, so the
        # variable name must carry both.  A ${FUZZER}_FUZZARGS is read by
        # nothing and fails silently.
        for t in "${TARGETS[@]}"; do
            echo "${FUZZER}_${t}_FUZZARGS=\"$FUZZARGS\""
        done
    fi
} > "$RC"

echo "== rc       $RC"
sed 's/^/     /' "$RC"

if [ "$DRY_RUN" = 1 ]; then
    echo "-- would run: cd $MAGMA && ./tools/captain/run.sh tools/captain/$RC_NAME"
    exit 0
fi

LOG="$MAGMA/workdir/log/campaign_${FUZZER}_$(IFS=-; echo "${TARGETS[*]}")_${ARM}_$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
cp "$RC" "${LOG%.log}.rc"

echo "== log      $LOG"
[ "$CACHE_ON_DISK" = 1 ] || echo "== captain will ask for sudo, to mount the tmpfs over workdir/cache"

cd "$MAGMA"
./tools/captain/run.sh "tools/captain/$RC_NAME" 2>&1 | tee "$LOG"

echo
echo "== done.  results:"
echo "     $MAGMA/workdir/ar/$FUZZER/<target>/<program>/<cid>/ball.tar"
echo "   summarize:"
echo "     $SYMSAN/tools/magma/results.sh"
echo "   recover the corpus:"
echo "     $SYMSAN/tools/magma/extract-corpus.sh --target ${TARGETS[0]} /tmp/corpus"
