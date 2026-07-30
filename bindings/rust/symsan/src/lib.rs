//! Safe Rust bindings for [SymSan](https://github.com/R-Fuzz/symsan).
//!
//! SymSan is a concolic (concrete + symbolic) execution engine: it runs an
//! instrumented target on a concrete input, records the symbolic constraints
//! the target's branches imposed on that input, and solves them to produce new
//! inputs that take the *other* side of those branches.
//!
//! This crate is a thin safe layer over the C ABI in `include/symsan_c.h`.  The
//! parsing and solving are the C++ implementation in `driver/session/`, shared
//! with the AFL++ custom mutator, so both front-ends behave identically by
//! construction rather than by two people keeping two copies in step.
//!
//! It has no LibAFL dependency -- see the `libafl-symsan` crate for that.
//!
//! # Example
//!
//! ```no_run
//! use symsan::{Config, Session};
//!
//! # fn main() -> Result<(), symsan::Error> {
//! let config = Config::new("/path/to/target.symsan", "/tmp/.cur_input")
//!     .arg("/path/to/target.symsan")
//!     .arg("/tmp/.cur_input")   // the target reads its input from this path
//!     .use_stdin(false)
//!     .jigsaw(true)
//!     .z3(true);
//!
//! let mut session = Session::new()?;
//! session.init(&config)?;
//!
//! let n = session.trace(b"AAAAAAAAAAAAAAAAAAAA")?;
//! println!("{n} solving tasks");
//!
//! while let Some(solution) = session.next_solution() {
//!     let interesting = run_and_check(&solution);
//!     session.report_result(interesting);
//! }
//! # Ok(())
//! # }
//! # fn run_and_check(_: &[u8]) -> bool { false }
//! ```
//!
//! # One session per process
//!
//! SymSan's launcher keeps its configuration in a C file-global, so a process
//! can host exactly one [`Session`].  [`Session::new`] returns [`Error::Busy`]
//! for a second one rather than letting the two corrupt each other.  This is
//! not a practical limit: fuzzers scale by forking, and the union-table shared
//! memory is already named per-pid.

#![warn(missing_docs)]

use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

/// Raw FFI declarations, generated from `include/symsan_c.h` by bindgen.
///
/// Private: everything here is `unsafe` and mirrors C's conventions (raw
/// pointers, `int` booleans, sentinel returns).  The rest of this file is the
/// translation into Rust's conventions, and is the only thing users touch.
#[allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
#[allow(missing_docs, clippy::all)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// The SymSan install prefix this crate was linked against, e.g. `.../b4`.
///
/// `bin/ko-clang` and `lib/symsan/` live under it. Baked in by `build.rs`, so
/// a front-end can find the toolchain that matches the runtime it is talking
/// to instead of hoping `$PATH` agrees.
pub const BUILD_DIR: &str = env!("SYMSAN_BUILD_DIR_RESOLVED");

/// The SymSan source tree this crate was built from.
pub const REPO_ROOT: &str = env!("SYMSAN_REPO_ROOT");

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/// Anything that can go wrong talking to SymSan.
#[derive(Debug)]
pub enum Error {
    /// An argument was missing, out of range, or self-contradictory.
    Invalid(String),
    /// The C++ side reported failure. The string is SymSan's own diagnostic.
    Failed(String),
    /// A session already exists in this process; see the module docs.
    Busy(String),
    /// A call needs [`Session::init`] to have run first.
    NotReady,
    /// Allocation failed inside the C++ layer.
    NoMemory,
    /// A Rust string contained an interior NUL and cannot become a C string.
    Nul(NulError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(m) => write!(f, "invalid argument: {m}"),
            Error::Failed(m) => write!(f, "symsan failed: {m}"),
            Error::Busy(m) => write!(f, "session already active: {m}"),
            Error::NotReady => write!(f, "session has not been initialized"),
            Error::NoMemory => write!(f, "out of memory"),
            Error::Nul(e) => write!(f, "string contains an interior NUL: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Nul(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NulError> for Error {
    fn from(e: NulError) -> Self {
        Error::Nul(e)
    }
}

/// Read the thread-local diagnostic the C layer leaves behind on failure.
///
/// # Safety
/// `symsan_last_error` never returns NULL and the string is valid until the
/// next failing call *on this thread*, so copying it out immediately is sound.
fn last_error() -> String {
    unsafe { CStr::from_ptr(sys::symsan_last_error()) }
        .to_string_lossy()
        .into_owned()
}

/// Turn a C status code into a `Result`.
///
/// bindgen renders `symsan_status_t` as a `#[repr(transparent)]` newtype with
/// the values as associated constants, rather than as a Rust `enum`: an `enum`
/// holding a value outside its variants is instant undefined behaviour, and a
/// value arriving over FFI cannot be proven to be in range.  Hence the
/// `Status::CONST` paths and the catch-all arm below.
fn check(status: sys::symsan_status_t) -> Result<(), Error> {
    use sys::symsan_status_t as Status;
    match status {
        Status::SYMSAN_OK => Ok(()),
        Status::SYMSAN_ERR_INVALID => Err(Error::Invalid(last_error())),
        Status::SYMSAN_ERR_NOMEM => Err(Error::NoMemory),
        Status::SYMSAN_ERR_BUSY => Err(Error::Busy(last_error())),
        Status::SYMSAN_ERR_NOT_READY => Err(Error::NotReady),
        _ => Err(Error::Failed(last_error())),
    }
}

/// The result of one solver attempt; mirrors `rgd::solver_result_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolverResult {
    /// Satisfiable: a mutated input was produced.
    Sat,
    /// Proved unsatisfiable; no solver in the ladder can do better.
    Unsat,
    /// Every solver gave up before deciding.
    Timeout,
    /// Something went wrong; see [`Error`] via the caller's own reporting.
    Error,
}

impl From<sys::symsan_solver_result_t> for SolverResult {
    fn from(r: sys::symsan_solver_result_t) -> Self {
        use sys::symsan_solver_result_t as Raw;
        match r {
            Raw::SYMSAN_SOLVER_SAT => SolverResult::Sat,
            Raw::SYMSAN_SOLVER_UNSAT => SolverResult::Unsat,
            Raw::SYMSAN_SOLVER_TIMEOUT => SolverResult::Timeout,
            _ => SolverResult::Error,
        }
    }
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

/// How to run the target and which solvers to use.
///
/// The C struct this becomes only *borrows* its strings, so `Config` owns the
/// [`CString`]s and hands out pointers into them for exactly as long as the
/// FFI call runs.  That is why `Config::as_raw` is private and why
/// nothing here returns a raw pointer to the caller.
///
/// Built with a chained-setter (builder) style:
///
/// ```
/// # use symsan::Config;
/// let config = Config::new("./target.symsan", "/tmp/.cur_input")
///     .args(["./target.symsan", "/tmp/.cur_input"])
///     .use_stdin(false)
///     .jigsaw(true);
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    symsan_bin: CString,
    input_file: CString,
    output_dir: Option<CString>,
    args: Vec<CString>,
    use_stdin: bool,

    use_i2s: bool,
    use_jigsaw: bool,
    use_z3: bool,
    nested_solving: bool,

    trace_bounds: bool,
    solve_ub: bool,
    exit_on_memerror: bool,
    force_stdin: bool,
    save_solved: bool,
    debug: bool,
    timeout_ms: u32,

    max_ast_size: usize,
    max_local_branch_counter: u8,
    max_input_size: usize,

    branch_map: Option<CString>,
    forkserver: bool,
    validate_coverage: bool,
}

/// Convert to a `CString`, replacing any interior NUL by truncating at it.
///
/// Paths from the OS cannot contain NUL, so this only fires on a caller
/// passing something odd; failing the whole build for it would be unhelpful,
/// but so would silently mangling it, hence the `Result` at the call sites that
/// can propagate one.
fn cstring(s: impl AsRef<str>) -> CString {
    CString::new(s.as_ref()).unwrap_or_else(|e| {
        let bytes = e.into_vec();
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        CString::new(&bytes[..nul]).expect("truncated at the first NUL")
    })
}

impl Config {
    /// Start from the C layer's defaults.
    ///
    /// * `symsan_bin` -- the target built with `ko-clang` and `KO_USE_FASTGEN=1`
    /// * `input_file` -- a scratch path the session writes each traced input
    ///   to.  If the target takes a filename on the command line, the matching
    ///   entry in [`args`](Config::args) must be this same path.
    pub fn new(symsan_bin: impl AsRef<str>, input_file: impl AsRef<str>) -> Self {
        // Ask C for the defaults rather than repeating them here, so adding a
        // field to symsan_config_t does not silently change behaviour in Rust.
        let mut raw = std::mem::MaybeUninit::<sys::symsan_config_t>::uninit();
        // SAFETY: symsan_config_init fully initializes the struct (it memsets
        // first), and we only read it after the call.
        let raw = unsafe {
            sys::symsan_config_init(raw.as_mut_ptr());
            raw.assume_init()
        };

        Self {
            symsan_bin: cstring(symsan_bin),
            input_file: cstring(input_file),
            output_dir: None,
            args: Vec::new(),
            use_stdin: raw.use_stdin != 0,
            use_i2s: raw.use_i2s != 0,
            use_jigsaw: raw.use_jigsaw != 0,
            use_z3: raw.use_z3 != 0,
            nested_solving: raw.nested_solving != 0,
            trace_bounds: raw.trace_bounds != 0,
            solve_ub: raw.solve_ub != 0,
            exit_on_memerror: raw.exit_on_memerror != 0,
            force_stdin: raw.force_stdin != 0,
            save_solved: raw.save_solved != 0,
            debug: raw.debug != 0,
            timeout_ms: raw.timeout_ms,
            max_ast_size: raw.max_ast_size,
            max_local_branch_counter: raw.max_local_branch_counter,
            max_input_size: raw.max_input_size,
            branch_map: None,
            forkserver: raw.forkserver != 0,
            validate_coverage: raw.validate_coverage != 0,
        }
    }

    /// Overlay the `SYMSAN_*` environment variables.
    ///
    /// Honours the same knobs as the AFL++ mutator -- `SYMSAN_TARGET`,
    /// `SYMSAN_OUTPUT_DIR`, `SYMSAN_NO_I2S`, `SYMSAN_USE_JIGSAW`, `SYMSAN_USE_Z3`,
    /// `SYMSAN_USE_NESTED`, `SYMSAN_TRACE_BOUNDS`, `SYMSAN_SOLVE_UB`,
    /// `SYMSAN_DONT_EXIT_ON_MEMERROR`, `SYMSAN_FORCE_STDIN`,
    /// `SYMSAN_SAVE_SOLVED`, `SYMSAN_FORKSRV`, `SYMSAN_BRANCH_MAP` -- by calling the same C++
    /// code, so the two front-ends cannot disagree about what a variable means.
    ///
    /// `input_file`, `args` and `use_stdin` are left alone; they are the
    /// front-end's business, not the environment's.
    ///
    /// Requires `SYMSAN_TARGET` to be set, and overwrites `symsan_bin` with it.
    pub fn from_env(input_file: impl AsRef<str>) -> Result<Self, Error> {
        let mut raw = std::mem::MaybeUninit::<sys::symsan_config_t>::uninit();
        // SAFETY: _init initializes the struct; _from_env only overwrites
        // fields, and reports through its return value rather than by leaving
        // the struct half-written.
        let raw = unsafe {
            sys::symsan_config_init(raw.as_mut_ptr());
            check(sys::symsan_config_from_env(raw.as_mut_ptr()))?;
            raw.assume_init()
        };

        // SAFETY: on success the C layer guarantees symsan_bin points at a
        // NUL-terminated environment string; output_dir is either NULL or the
        // same.  We copy both immediately, so later setenv() cannot dangle us.
        let symsan_bin = unsafe { CStr::from_ptr(raw.symsan_bin) }.to_owned();
        let output_dir = if raw.output_dir.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(raw.output_dir) }.to_owned())
        };
        let branch_map = if raw.branch_map.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(raw.branch_map) }.to_owned())
        };

        Ok(Self {
            symsan_bin,
            input_file: cstring(input_file),
            output_dir,
            args: Vec::new(),
            use_stdin: raw.use_stdin != 0,
            use_i2s: raw.use_i2s != 0,
            use_jigsaw: raw.use_jigsaw != 0,
            use_z3: raw.use_z3 != 0,
            nested_solving: raw.nested_solving != 0,
            trace_bounds: raw.trace_bounds != 0,
            solve_ub: raw.solve_ub != 0,
            exit_on_memerror: raw.exit_on_memerror != 0,
            force_stdin: raw.force_stdin != 0,
            save_solved: raw.save_solved != 0,
            debug: raw.debug != 0,
            timeout_ms: raw.timeout_ms,
            max_ast_size: raw.max_ast_size,
            max_local_branch_counter: raw.max_local_branch_counter,
            max_input_size: raw.max_input_size,
            branch_map,
            forkserver: raw.forkserver != 0,
            validate_coverage: raw.validate_coverage != 0,
        })
    }

    /// Append one `argv` entry. `argv[0]` is conventionally the target path.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(cstring(arg));
        self
    }

    /// Replace `argv` wholesale.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args = args.into_iter().map(cstring).collect();
        self
    }

    /// Where to write solved inputs when [`save_solved`](Config::save_solved)
    /// is on. Defaults to the working directory.
    #[must_use]
    pub fn output_dir(mut self, dir: impl AsRef<str>) -> Self {
        self.output_dir = Some(cstring(dir));
        self
    }

    /// Whether the target reads its input from stdin instead of `input_file`.
    #[must_use]
    pub fn use_stdin(mut self, yes: bool) -> Self {
        self.use_stdin = yes;
        self
    }

    /// Run the input-to-state solver, the first rung of the ladder. On by
    /// default, and the one to leave on: it is nearly free, and it is what
    /// cracks the "input byte compared against a constant" shape that most of
    /// a real target's branches turn out to be. Turn it off only to measure
    /// what the solvers behind it can do without its help.
    #[must_use]
    pub fn i2s(mut self, yes: bool) -> Self {
        self.use_i2s = yes;
        self
    }

    /// Add the JIT/gradient-descent solver to the ladder. Much faster than Z3
    /// on the constraints fuzzing produces, and it is what makes the RGD stack
    /// worth using; you almost always want this on.
    #[must_use]
    pub fn jigsaw(mut self, yes: bool) -> Self {
        self.use_jigsaw = yes;
        self
    }

    /// Add Z3 as the last resort in the ladder.
    #[must_use]
    pub fn z3(mut self, yes: bool) -> Self {
        self.use_z3 = yes;
        self
    }

    /// Fold the path constraints into each task. More precise, more expensive.
    #[must_use]
    pub fn nested_solving(mut self, yes: bool) -> Self {
        self.nested_solving = yes;
        self
    }

    /// Track allocation bounds so out-of-bounds accesses can be detected.
    #[must_use]
    pub fn trace_bounds(mut self, yes: bool) -> Self {
        self.trace_bounds = yes;
        self
    }

    /// Solve for undefined behaviour as well as coverage. Implies
    /// [`trace_bounds`](Config::trace_bounds).
    #[must_use]
    pub fn solve_ub(mut self, yes: bool) -> Self {
        self.solve_ub = yes;
        if yes {
            self.trace_bounds = true;
        }
        self
    }

    /// Whether the target should stop at the first memory error. Default true.
    #[must_use]
    pub fn exit_on_memerror(mut self, yes: bool) -> Self {
        self.exit_on_memerror = yes;
        self
    }

    /// Write every solved input to [`output_dir`](Config::output_dir). A
    /// debugging aid; it costs a file write per solution.
    #[must_use]
    pub fn save_solved(mut self, yes: bool) -> Self {
        self.save_solved = yes;
        self
    }

    /// Verbose output from the target's runtime.
    #[must_use]
    pub fn debug(mut self, yes: bool) -> Self {
        self.debug = yes;
        self
    }

    /// Per-run timeout in milliseconds. Also arms the deadloop guard, which
    /// kills a target that keeps emitting events forever. `0` waits forever.
    #[must_use]
    pub fn timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Skip constraint trees larger than this. Guards against one pathological
    /// branch eating the whole time budget.
    #[must_use]
    pub fn max_ast_size(mut self, n: usize) -> Self {
        self.max_ast_size = n;
        self
    }

    /// How many times a single branch may be traced within one input, so a
    /// hot loop does not crowd out everything else.
    #[must_use]
    pub fn max_local_branch_counter(mut self, n: u8) -> Self {
        self.max_local_branch_counter = n;
        self
    }

    /// Largest input that will be traced or emitted.
    #[must_use]
    pub fn max_input_size(mut self, n: usize) -> Self {
        self.max_input_size = n;
        self
    }

    /// Share a branch namespace with the fuzzer.
    ///
    /// `path` is the file a patched AFL++ writes when `AFL_LLVM_DOCUMENT_IDS`
    /// is set while building the *fuzzer's* copy of the target (see
    /// `patches/aflpp-document-ids.patch`).  It says which AFL++ edge id each
    /// source-level branch direction corresponds to, which is what lets
    /// [`Session::set_coverage`] tell the session that a branch has already
    /// been covered and is not worth solving for again.
    ///
    /// Without this, the session only knows what it has seen itself, so every
    /// freshly started session re-solves branches the fuzzer covered long ago.
    #[must_use]
    pub fn branch_map(mut self, path: impl AsRef<str>) -> Self {
        self.branch_map = Some(cstring(path));
        self
    }

    /// Trade a per-run `execv` for a `fork`.
    ///
    /// With this on, the target is spawned once and forks a child per input,
    /// which skips the dynamic link and the shadow and union table setup every
    /// time -- most of what a short run spends its time on.
    ///
    /// It applies only to file input (a stdin target needs its fd wired up per
    /// run, which cannot be done from outside a running process) and only to
    /// targets whose backend has a fork server.  Neither case is an error: the
    /// session falls back to exec'ing per run, so this is always safe to set.
    #[must_use]
    pub fn forkserver(mut self, enable: bool) -> Self {
        self.forkserver = enable;
        self
    }

    /// Record which branch directions each trace takes, so that
    /// [`Session::check_coverage`] can hold the branch map against ground
    /// truth.
    ///
    /// Off by default.  [`Stats::mapped_branches`] only says how *much* of the
    /// map lands; a map that resolved every branch to the wrong edge would
    /// report a perfect ratio while silently suppressing every solve, and this
    /// is what tells the two apart.  It costs a hash insert per branch, so it
    /// is a diagnostic rather than something a fuzzing run wants on.
    #[must_use]
    pub fn validate_coverage(mut self, enable: bool) -> Self {
        self.validate_coverage = enable;
        self
    }

    /// The scratch file inputs are staged into.
    pub fn input_file_path(&self) -> PathBuf {
        PathBuf::from(self.input_file.to_string_lossy().into_owned())
    }

    /// Build the C view of this config.
    ///
    /// Returns the struct *and* the `argv` pointer array, because the struct
    /// points into that array: the caller must keep the `Vec` alive for as long
    /// as it uses the struct.  Rust cannot express "these two must live
    /// together" in a return type, so they are returned together as a tuple and
    /// this stays private.
    fn as_raw(&self) -> (sys::symsan_config_t, Vec<*const c_char>) {
        let argv: Vec<*const c_char> = self.args.iter().map(|a| a.as_ptr()).collect();

        let mut raw = std::mem::MaybeUninit::<sys::symsan_config_t>::uninit();
        // SAFETY: initializes every field, so the reads below are defined.
        let mut raw = unsafe {
            sys::symsan_config_init(raw.as_mut_ptr());
            raw.assume_init()
        };

        raw.symsan_bin = self.symsan_bin.as_ptr();
        raw.input_file = self.input_file.as_ptr();
        raw.output_dir = self
            .output_dir
            .as_ref()
            .map_or(std::ptr::null(), |d| d.as_ptr());
        raw.argv = argv.as_ptr();
        raw.argc = argv.len() as i32;
        raw.use_stdin = self.use_stdin.into();
        raw.use_i2s = self.use_i2s.into();
        raw.use_jigsaw = self.use_jigsaw.into();
        raw.use_z3 = self.use_z3.into();
        raw.nested_solving = self.nested_solving.into();
        raw.trace_bounds = self.trace_bounds.into();
        raw.solve_ub = self.solve_ub.into();
        raw.exit_on_memerror = self.exit_on_memerror.into();
        raw.force_stdin = self.force_stdin.into();
        raw.save_solved = self.save_solved.into();
        raw.debug = self.debug.into();
        raw.timeout_ms = self.timeout_ms;
        raw.max_ast_size = self.max_ast_size;
        raw.max_local_branch_counter = self.max_local_branch_counter;
        raw.max_input_size = self.max_input_size;
        raw.branch_map = self
            .branch_map
            .as_ref()
            .map_or(std::ptr::null(), |p| p.as_ptr());
        raw.forkserver = self.forkserver.into();
        raw.validate_coverage = self.validate_coverage.into();

        (raw, argv)
    }
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

/// Counters accumulated over the life of a [`Session`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Symbolic branches seen.
    pub total_branches: u64,
    /// Branches whose other side looked worth solving for.
    pub branches_to_solve: u64,
    /// Solving tasks queued.
    pub total_tasks: u64,
    /// Tasks a solver satisfied.
    pub solved_tasks: u64,
    /// Branches a solution actually flipped, as reported by the front-end
    /// through [`Session::report_result`].
    pub solved_branches: u64,
    /// Branch directions the branch map resolved to fuzzer edge ids.
    ///
    /// Zero unless [`Config::branch_map`] was set.  With a map, the split
    /// between this and [`unmapped_branches`](Stats::unmapped_branches) is the
    /// diagnostic for whether the two builds of the target actually agree on
    /// branch names: a near-zero ratio usually means the two clangs disagree
    /// about column numbers, or that the fuzzer's build was missing `-g`.
    pub mapped_branches: u64,
    /// Branch directions the branch map had nothing to say about, so the
    /// session fell back to its own coverage.
    pub unmapped_branches: u64,
}

/// What [`Session::check_coverage`] found: does the branch map point at the
/// edges the fuzzer's build actually covers?
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JoinReport {
    /// Distinct branch directions the last trace took.
    pub executed: usize,
    /// Of those, the ones the branch map resolved to exactly one edge id.
    pub checked: usize,
    /// Of the checked ones, those whose edge the fuzzer's build did *not*
    /// record.  Any non-zero value is a bug.
    pub violations: usize,
    /// Directions resolving to several edge ids, because the branch was
    /// inlined.  A run takes one of the copies, so these can only be checked
    /// as "at least one covered".
    pub ambiguous: usize,
    /// Of the ambiguous ones, those where *none* of the edge ids was recorded.
    pub ambiguous_violations: usize,
    /// Directions the map had nothing to say about.  Expected to be non-zero
    /// -- AFL++ prunes blocks -- and merely costs opportunities.
    pub unmapped: usize,
}

impl JoinReport {
    /// True when nothing contradicted the map.
    pub fn is_consistent(&self) -> bool {
        self.violations == 0 && self.ambiguous_violations == 0
    }
}

// ---------------------------------------------------------------------------
// the session
// ---------------------------------------------------------------------------

/// A live SymSan concolic-execution session.
///
/// Owns the instrumented target's launcher, the union-table shared memory, the
/// AST parser and the solver ladder.  Dropping it releases all of them.
///
/// Only one may exist per process; see the [module docs](crate).
pub struct Session {
    /// `NonNull` rather than `*mut`: it is never null while we hold it, and
    /// that lets `Option<Session>` reuse the null pointer as its `None`.
    raw: NonNull<sys::symsan_session_t>,
    /// Cached so [`input_file`](Session::input_file) does not have to re-cross
    /// the FFI boundary and re-validate UTF-8 on every call.
    input_file: PathBuf,
}

// SAFETY: the handle is not shared with any other thread and every method
// takes &self or &mut self, so Rust's borrow rules already serialize access.
// The C++ side keeps no thread-local state for a session.  Send, but
// deliberately not Sync: two threads calling next_solution() concurrently would
// race on the session's internal output buffer, and &self methods like stats()
// would then read it mid-write.
unsafe impl Send for Session {}

impl Session {
    /// Allocate a session.
    ///
    /// Returns [`Error::Busy`] if one is already live in this process.  You
    /// still have to call [`init`](Session::init) before doing anything.
    pub fn new() -> Result<Self, Error> {
        // SAFETY: no arguments; returns NULL on failure, which we check.
        let raw = unsafe { sys::symsan_session_create() };
        match NonNull::new(raw) {
            Some(raw) => Ok(Self {
                raw,
                input_file: PathBuf::new(),
            }),
            None => Err(Error::Busy(last_error())),
        }
    }

    /// Map the union table, build the parser and solver ladder, and open the
    /// input file. Call exactly once.
    ///
    /// Separate from [`new`](Session::new) because a front-end often only
    /// learns its target's `argv` after start-up.
    pub fn init(&mut self, config: &Config) -> Result<(), Error> {
        if config.args.is_empty() {
            return Err(Error::Invalid(
                "config has no argv; at least argv[0] is required".into(),
            ));
        }

        // `argv` must outlive the call because `raw` points into it.  Binding
        // it to a local here (rather than `let (raw, _) = ...`) is what keeps
        // it alive: `_` would drop it immediately.
        let (raw, argv) = config.as_raw();

        // SAFETY: raw's pointers all borrow from `config` and `argv`, both of
        // which outlive this call. The C side copies what it keeps.
        let status = unsafe { sys::symsan_session_init(self.raw.as_ptr(), &raw) };
        drop(argv);
        check(status)?;

        self.input_file = config.input_file_path();
        Ok(())
    }

    /// Run the target on `input` and turn the branches it hits into solving
    /// tasks.
    ///
    /// Discards any tasks left over from the previous input, so the usual shape
    /// is `trace` once, then drain [`next_solution`](Session::next_solution).
    ///
    /// Returns the number of tasks queued. Zero is normal and just means the
    /// input found nothing new worth solving.
    pub fn trace(&mut self, input: &[u8]) -> Result<usize, Error> {
        // SAFETY: `input` is a valid slice for the duration of the call, and
        // the C side copies what it needs before returning.
        let n = unsafe {
            sys::symsan_session_trace(self.raw.as_ptr(), input.as_ptr(), input.len())
        };
        if n < 0 {
            // trace() returns a count, so it smuggles errors back as negative
            // status codes rather than as a symsan_status_t; wrap it back up so
            // check() can decode it. Cannot be SYMSAN_OK here, hence unwrap_err.
            return Err(check(sys::symsan_status_t(n)).unwrap_err());
        }
        Ok(n as usize)
    }

    /// The next solved input, or `None` when the tasks from the last
    /// [`trace`](Session::trace) are exhausted.
    ///
    /// Copies out of the session's buffer, so the returned `Vec` is yours and
    /// there is no borrow to juggle before calling
    /// [`report_result`](Session::report_result).  The copy is free in
    /// practice: solving takes milliseconds, and every consumer (LibAFL's
    /// `BytesInput`, a `write()`) wants an owned buffer anyway.  Use
    /// [`next_solution_ref`](Session::next_solution_ref) to skip it.
    pub fn next_solution(&mut self) -> Option<Vec<u8>> {
        self.next_solution_ref().map(<[u8]>::to_vec)
    }

    /// Zero-copy [`next_solution`](Session::next_solution).
    ///
    /// The slice borrows the session's internal buffer, which the next call to
    /// `next_solution*` or [`trace`](Session::trace) overwrites -- the `&mut
    /// self` borrow is what stops you from doing that while holding it.  It
    /// also means you cannot call [`report_result`](Session::report_result)
    /// until the slice goes out of scope, so copy what you need first.
    pub fn next_solution_ref(&mut self) -> Option<&[u8]> {
        let mut len: usize = 0;
        // SAFETY: `len` is a valid out-pointer. The returned pointer is either
        // NULL or valid for `len` bytes until our next &mut self call, which
        // the borrow checker now prevents for as long as the slice lives.
        let ptr = unsafe { sys::symsan_session_next_solution(self.raw.as_ptr(), &mut len) };
        if ptr.is_null() {
            return None;
        }
        // A non-NULL pointer with length 0 would make from_raw_parts UB-ish;
        // treat it as "no solution" rather than fabricating an empty slice.
        if len == 0 {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    /// Tell the session whether the last solution was interesting.
    ///
    /// `true` marks the branch solved and moves on. `false` escalates to the
    /// next solver in the ladder for the same task, so a cheap solver's near
    /// miss gets a second try from an expensive one.
    ///
    /// This is the concrete advantage a LibAFL stage has over the AFL++
    /// mutator: AFL++ had to *guess* by comparing queue-entry filenames,
    /// whereas a stage sees its own `ExecuteInputResult` and can just say.
    ///
    /// Not reporting at all is equivalent to reporting `false`.
    pub fn report_result(&mut self, interesting: bool) {
        // SAFETY: valid handle; the call cannot fail.
        unsafe { sys::symsan_session_report_result(self.raw.as_ptr(), interesting.into()) }
    }

    /// Hand the session a snapshot of the fuzzer's coverage map, so it stops
    /// solving for branches the fuzzer has already reached.
    ///
    /// `map` is indexed by AFL++ edge id and read as "non-zero means covered",
    /// so either a hit-count map or LibAFL's history map works.  It is copied,
    /// and it only affects branches the [`Config::branch_map`] resolves --
    /// everything else keeps behaving as if this had not been called.
    ///
    /// Call it before [`trace`](Session::trace).  Returns [`Error::Invalid`] if
    /// the session was initialized without a branch map, since then there is no
    /// way to know which entry of `map` belongs to which branch.
    pub fn set_coverage(&mut self, map: &[u8]) -> Result<(), Error> {
        // SAFETY: valid handle; `map` is a valid slice for the duration of the
        // call and the C side copies it before returning.
        check(unsafe {
            sys::symsan_session_set_coverage(self.raw.as_ptr(), map.as_ptr(), map.len())
        })
    }

    /// Hold the branch map against ground truth for the input just traced.
    ///
    /// Where [`set_coverage`](Session::set_coverage) *uses* the map, this
    /// *checks* it.  `covered` is the set of AFL++ edge ids the **fuzzer's**
    /// build of the same target recorded for the same bytes -- a corpus
    /// entry's `MapIndexesMetadata`, or the output of `afl-showmap`.  Every
    /// direction the trace took should resolve to an edge in there, so a
    /// non-zero [`JoinReport::violations`] means the map names the wrong edge,
    /// or the two builds took different paths.
    ///
    /// The converse says nothing and is not reported: the fuzzer records every
    /// edge it walks, and the ones whose condition did not depend on the input
    /// never reach a concolic trace.
    ///
    /// Needs both [`Config::branch_map`] and [`Config::validate_coverage`];
    /// returns [`Error::Invalid`] otherwise.
    pub fn check_coverage(&self, covered: &[u32]) -> Result<JoinReport, Error> {
        let mut raw = sys::symsan_join_report_t {
            executed: 0,
            checked: 0,
            violations: 0,
            ambiguous: 0,
            ambiguous_violations: 0,
            unmapped: 0,
        };
        // SAFETY: valid handle, valid slice for the duration of the call, and a
        // valid out-pointer.
        check(unsafe {
            sys::symsan_session_check_coverage(
                self.raw.as_ptr(),
                covered.as_ptr(),
                covered.len(),
                &mut raw,
            )
        })?;
        Ok(JoinReport {
            executed: raw.executed,
            checked: raw.checked,
            violations: raw.violations,
            ambiguous: raw.ambiguous,
            ambiguous_violations: raw.ambiguous_violations,
            unmapped: raw.unmapped,
        })
    }

    /// Counters for the whole session.
    pub fn stats(&self) -> Stats {
        let mut raw = sys::symsan_stats_t {
            total_branches: 0,
            branches_to_solve: 0,
            total_tasks: 0,
            solved_tasks: 0,
            solved_branches: 0,
            mapped_branches: 0,
            unmapped_branches: 0,
        };
        // SAFETY: valid handle and a valid out-pointer. Errors here can only
        // mean a null argument, which we just ruled out, so the zeroed struct
        // is a fine fallback.
        unsafe { sys::symsan_session_stats(self.raw.as_ptr(), &mut raw) };
        Stats {
            total_branches: raw.total_branches,
            branches_to_solve: raw.branches_to_solve,
            total_tasks: raw.total_tasks,
            solved_tasks: raw.solved_tasks,
            solved_branches: raw.solved_branches,
            mapped_branches: raw.mapped_branches,
            unmapped_branches: raw.unmapped_branches,
        }
    }

    /// Dump the counters, the task-size histogram and each solver's own stats
    /// to a file descriptor.
    pub fn print_stats(&self, fd: i32) {
        // SAFETY: valid handle; a bad fd just makes the writes fail.
        unsafe { sys::symsan_session_print_stats(self.raw.as_ptr(), fd) }
    }

    /// Tasks still queued for the current input.
    pub fn pending_tasks(&self) -> usize {
        // SAFETY: valid handle.
        unsafe { sys::symsan_session_num_pending_tasks(self.raw.as_ptr()) }
    }

    /// How many solvers are in the ladder. Multiplied by the task count, this
    /// bounds how many times [`next_solution`](Session::next_solution) can
    /// return something.
    pub fn num_solvers(&self) -> usize {
        // SAFETY: valid handle.
        unsafe { sys::symsan_session_num_solvers(self.raw.as_ptr()) }
    }

    /// The scratch file [`trace`](Session::trace) stages inputs into.
    ///
    /// A front-end that passes a filename to the target must use this exact
    /// path in its `argv`, or the target will read something else.
    pub fn input_file(&self) -> &Path {
        &self.input_file
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: we own the handle, this runs once, and nothing can use it
        // afterwards. Releasing it also clears the one-session-per-process
        // flag, so a later Session::new() succeeds.
        unsafe { sys::symsan_session_destroy(self.raw.as_ptr()) }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("input_file", &self.input_file)
            .field("pending_tasks", &self.pending_tasks())
            .field("stats", &self.stats())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// Tests that need no live session, and so can run in parallel with each other.
/// The one that does need a session lives in `tests/session.rs`, alone in its
/// own binary; see the note at the top of that file.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_c_layer() {
        let cfg = Config::new("/bin/true", "/tmp/in");
        // These are the C++ ConcolicConfig defaults, read back through
        // symsan_config_init. If someone changes one on the C++ side this test
        // fails, which is the point: it is a tripwire, not a specification.
        assert!(cfg.exit_on_memerror, "exit_on_memerror should default on");
        assert_eq!(cfg.max_ast_size, 200);
        assert_eq!(cfg.max_local_branch_counter, 128);
        assert_eq!(cfg.max_input_size, 1 << 20);
        assert!(!cfg.save_solved, "save_solved is a debugging aid, default off");
        assert!(!cfg.debug);
        assert!(cfg.use_i2s, "i2s should default on; it is the cheap rung");
    }

    #[test]
    fn builder_setters_stick() {
        let cfg = Config::new("/bin/true", "/tmp/in")
            .args(["/bin/true", "/tmp/in"])
            .use_stdin(true)
            .i2s(false)
            .jigsaw(false)
            .z3(true)
            .timeout_ms(1234)
            .max_ast_size(42)
            .forkserver(true);
        assert_eq!(cfg.args.len(), 2);
        assert!(cfg.use_stdin);
        assert!(!cfg.use_i2s);
        assert!(!cfg.use_jigsaw);
        assert!(cfg.use_z3);
        assert_eq!(cfg.timeout_ms, 1234);
        assert_eq!(cfg.max_ast_size, 42);
        assert!(cfg.forkserver);
        assert_eq!(cfg.input_file_path(), Path::new("/tmp/in"));
    }

    #[test]
    fn solve_ub_implies_trace_bounds() {
        // Solving for undefined behaviour needs the allocation bounds that
        // trace_bounds records, so the setter turns it on rather than failing
        // mysteriously later.
        let cfg = Config::new("/bin/true", "/tmp/in").trace_bounds(false).solve_ub(true);
        assert!(cfg.trace_bounds);
    }

    #[test]
    fn as_raw_points_at_our_strings() {
        let cfg = Config::new("/bin/true", "/tmp/in").args(["a", "b", "c"]);
        let (raw, argv) = cfg.as_raw();
        assert_eq!(raw.argc, 3);
        assert_eq!(raw.argv, argv.as_ptr());
        // SAFETY: raw.symsan_bin borrows cfg.symsan_bin, which is still alive.
        let bin = unsafe { CStr::from_ptr(raw.symsan_bin) };
        assert_eq!(bin.to_str().unwrap(), "/bin/true");
        let a = unsafe { CStr::from_ptr(argv[0]) };
        assert_eq!(a.to_str().unwrap(), "a");
    }

    #[test]
    fn interior_nul_is_truncated_not_panicked_on() {
        // Paths from the OS cannot contain a NUL, so this only fires on a
        // caller passing something odd. Truncating beats aborting the fuzzer.
        let cfg = Config::new("/bin/tr\0ue", "/tmp/in");
        assert_eq!(cfg.symsan_bin.to_str().unwrap(), "/bin/tr");
    }

    #[test]
    fn error_is_a_real_error() {
        // Sanity-check the Display/Error impls so `?` in a caller's main()
        // prints something useful.
        let e = Error::Busy("already live".into());
        assert!(e.to_string().contains("already live"));
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn build_dir_looks_like_an_install_prefix() {
        assert!(
            Path::new(BUILD_DIR).join("lib/symsan").is_dir(),
            "BUILD_DIR={BUILD_DIR} does not hold lib/symsan"
        );
    }
}
