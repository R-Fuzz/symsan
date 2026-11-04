# Per-subject config. Usage: source subjects.sh; subj <name>
# Sets: SRC (build root), BIN (relative path of harness inside each role build),
#       ARGS (args; "@@" = file input, empty = stdin), SEEDS (seed dir)
subj() {
  NAME=$1; SRC=$EVAL/src/$1; COVSCRIPT=
  case $1 in
    libyaml)     BIN=tests/run-parser-test-suite; ARGS="";      SEEDS=$ART/libyaml/seeds;;
    libmatheval) BIN=program;                     ARGS="";      SEEDS=$ART/libmatheval/seeds;;
    bc)          BIN=bc/bc;                       ARGS="";      SEEDS=$ART/bc/seeds;;
    confetti)    BIN=parse;                       ARGS="";      SEEDS=$ART/confetti/seeds;;
    krep)        BIN=krep;                        ARGS="test @@"; SEEDS=$ART/krep/seeds;;
    oggenc)      BIN=oggenc/oggenc;               ARGS="@@";    SEEDS=$ART/oggenc/seeds;;
    woff2)       BIN=woff2_decompress;            ARGS="@@";    SEEDS=$ART/woff2/seeds;;
    *) subj_ct $1 && return 0; echo "unknown subject $1" >&2; return 1;;
  esac
  if [ -f $EVAL/scripts/subjects.local.sh ]; then source $EVAL/scripts/subjects.local.sh; fi; return 0
}
# Cottontail subjects (reconstructed drivers; file argument like Cottontail's "<bin> @@")
subj_ct() {
  case $1 in
    libxml2)  BIN=build/xmllint;        ARGS="@@";;
    libexpat) BIN=expat/build/xmlwf/xmlwf; ARGS="@@";;
    sqlite)   BIN=sqlite_driver;        ARGS="@@";;
    unqlite)  BIN=unqlite_driver;       ARGS="@@";;
    mujs)     BIN=mujs;                 ARGS="@@";;
    quickjs)  BIN=build/qjs;            ARGS="@@";;
    json-c)   BIN=build/apps/json_parse; ARGS="@@";;
    jansson)  BIN=jansson_driver;       ARGS="@@";;
    *) return 1;;
  esac
  NAME=$1; SRC=$EVAL/src/$1; SEEDS=$EVAL/cottontail/seeds/$1; COVSCRIPT=$EVAL/scripts/coverage_ct.sh; return 0
}
